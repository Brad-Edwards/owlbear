#!/usr/bin/env python3
"""Build committed ARM64 sources, or verify an archive/extracted installation.

No cloud calls, module loading, attack execution, or experiment data collection.
"""

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zlib


SCHEMA = "owlbear.artifact/v1"
REQUIRED = {
    "daemon/owlbeard", "game/owlbear-game", "kernel/owlbear.ko",
    "ebpf/owlbear_lsm.bpf.o", "ebpf/owlbear_trace.bpf.o",
    "ebpf/owlbear_kprobe.bpf.o", "ebpf/owlbear_net.bpf.o",
    "cheats/preload_hook.so", "cheats/speed_hook.so",
    "signatures/default.sigs", "scripts/verify.sh",
    "scripts/research-artifact.py", "docs/research-artifacts.md", "LICENSE",
    "build-inputs/vmlinux.btf", "build-inputs/kernel.config",
    "build-inputs/Module.symvers",
}
CHEATS = (
    "mem_reader", "proc_mem_reader", "ptrace_injector", "ptrace_writer",
    "vm_writer", "mprotect_injector", "mprotect_inject_via_ptrace",
    "ld_preload_hook", "debug_reg_setter", "dev_mem_reader", "net_exfil",
    "speed_hack",
)
REQUIRED.update(f"cheats/{name}.bin" for name in CHEATS)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def command(args, cwd=None, env=None):
    return subprocess.check_output(args, cwd=cwd, env=env, text=True).strip()


def check_payload(manifest, files):
    """Validate all bytes without executing any payload or extracting an archive."""
    if manifest["schema"] != SCHEMA:
        raise ValueError("unsupported artifact schema")
    identity = dict(manifest["build"])
    build_id = identity.pop("build_id")
    if digest(encoded({"build": identity, "inputs": manifest["inputs"]})) != build_id:
        raise ValueError("build identity does not match its recorded inputs")
    expected = manifest["files"]
    if not REQUIRED <= expected.keys():
        raise ValueError("incomplete artifact payload")
    if set(files) != set(expected):
        raise ValueError("missing or unexpected artifact files")
    for name, (data, mode) in files.items():
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or str(path) != name:
            raise ValueError(f"unsafe payload path: {name}")
        if expected[name] != {"sha256": digest(data), "size": len(data), "mode": mode}:
            raise ValueError(f"payload integrity mismatch: {name}")
        if name.endswith((".bin", ".so", ".ko")) or name in {
            "daemon/owlbeard", "game/owlbear-game"
        } or name.endswith(".bpf.o"):
            # ELF64, little endian; EM_AARCH64=183, EM_BPF=247.
            machine = 247 if name.endswith(".bpf.o") else 183
            if (len(data) < 20 or data[:6] != b"\x7fELF\x02\x01"
                    or int.from_bytes(data[18:20], "little") != machine):
                raise ValueError(f"wrong ELF architecture: {name}")
    return manifest


def verify(path):
    path = Path(path)
    files = {}
    if path.is_dir():
        for item in path.rglob("*"):
            if item.is_symlink():
                raise ValueError(f"symlink in installation: {item}")
            if item.is_file():
                files[item.relative_to(path).as_posix()] = (
                    item.read_bytes(), item.stat().st_mode & 0o7777)
    else:
        with tarfile.open(path, "r:gz") as archive:
            root = None
            for member in archive.getmembers():
                parts = PurePosixPath(member.name).parts
                if (not member.isfile() or len(parts) < 2 or ".." in parts
                        or member.name.startswith("/")
                        or str(PurePosixPath(member.name)) != member.name):
                    raise ValueError(f"unsafe archive entry: {member.name}")
                root = root or parts[0]
                name = "/".join(parts[1:])
                if parts[0] != root or name in files:
                    raise ValueError("duplicate entry or multiple archive roots")
                files[name] = (archive.extractfile(member).read(), member.mode)
    manifest = json.loads(files.pop("manifest.json")[0])
    return check_payload(manifest, files)


def write_archive(path, root_name, files, epoch):
    # Fixed ordering, times, ownership and gzip header; no build-directory names.
    with path.open("xb") as output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=epoch) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT) as archive:
                for name, (data, mode) in sorted(files.items()):
                    member = tarfile.TarInfo(f"{root_name}/{name}")
                    member.size = len(data)
                    member.mode = mode
                    member.mtime = epoch
                    archive.addfile(member, io.BytesIO(data))


def build(args):
    if platform.machine() != "aarch64":
        raise ValueError("release builds require native ARM64 Linux (aarch64)")
    repo = Path(command(["git", "rev-parse", "--show-toplevel"]))
    commit = command(["git", "rev-parse", "HEAD"], repo)
    committed_script = subprocess.check_output(
        ["git", "show", f"{commit}:scripts/research-artifact.py"], cwd=repo)
    if Path(__file__).read_bytes() != committed_script:
        raise ValueError("commit changes to the artifact script before building")
    epoch = int(command(["git", "log", "-1", "--format=%ct", commit], repo))
    kdir = Path(args.kdir).resolve(strict=True)
    btf = Path(args.btf).resolve(strict=True)
    output = Path(args.output).absolute()
    if output.exists():
        raise ValueError(f"output already exists; choose a new directory: {output}")

    with tempfile.TemporaryDirectory(prefix="owlbear-build-") as temporary:
        workspace = Path(temporary)
        source = workspace / "source"
        source.mkdir()
        # Build only the recorded commit. Ignore checkout dirt and tracked binaries.
        archive_bytes = subprocess.check_output(["git", "archive", commit], cwd=repo)
        with tarfile.open(fileobj=io.BytesIO(archive_bytes)) as archive:
            archive.extractall(source, filter="data")
        version = (source / "VERSION").read_text().strip()
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
            raise ValueError("VERSION must contain a semantic version")
        kernel = (kdir / "include/config/kernel.release").read_text().strip()
        if not re.fullmatch(r"[a-zA-Z0-9._+-]+", kernel):
            raise ValueError("invalid kernel release")
        config = (kdir / ".config").read_bytes()
        if b"CONFIG_ARM64=y\n" not in config:
            raise ValueError("kernel headers are not configured for ARM64")
        tools = {name: command([executable, flag]).splitlines()[0] for name, executable, flag in (
            ("gcc", "gcc", "--version"), ("clang", "clang", "--version"),
            ("ld", "ld", "--version"), ("make", "make", "--version"),
            ("bpftool", args.bpftool, "version"),
        )}
        tools.update(python=sys.version, zlib=zlib.ZLIB_RUNTIME_VERSION)
        inputs = {
            "toolchain": tools,
            "os_release": Path("/etc/os-release").read_text(),
            "packages": command(["dpkg-query", "-W", "-f=${binary:Package}=${Version}\n"]),
            "btf_sha256": digest(btf.read_bytes()),
            "kernel_config_sha256": digest(config),
            "kernel_symvers_sha256": digest((kdir / "Module.symvers").read_bytes()),
            "flags": "-O2 -DNDEBUG; mapped source/header paths; kernel M=../source/kernel",
        }
        identity = {
            "schema": "owlbear.build/v1", "version": version, "source_commit": commit,
            "source_date_epoch": epoch, "architecture": "arm64", "kernel_release": kernel,
        }
        identity["build_id"] = digest(encoded({"build": identity, "inputs": inputs}))
        header = ["/* Generated for this committed release build. */"]
        for name, value in (
            ("OWL_BUILD_VERSION", version), ("OWL_BUILD_COMMIT", commit),
            ("OWL_BUILD_ID", identity["build_id"]),
            ("OWL_BUILD_INFO_JSON", json.dumps(identity, sort_keys=True)),
        ):
            header.append(f"#define {name} {json.dumps(value)}")
        (source / "include/owlbear_build.h").write_text("\n".join(header) + "\n")
        env = dict(os.environ, SOURCE_DATE_EPOCH=str(epoch), TZ="UTC", LC_ALL="C",
                   KBUILD_BUILD_USER="owlbear", KBUILD_BUILD_HOST="builder",
                   KBUILD_BUILD_VERSION="1", KBUILD_BUILD_TIMESTAMP=f"@{epoch}")
        # GCC 13's UBSAN location records ignore prefix maps. A private copy of
        # the configured headers lets Kbuild use a stable relative source path
        # without changing instrumentation or writing to system headers.
        headers = workspace / "headers"
        shutil.copytree(kdir, headers)
        flags = " ".join(f"-f{kind}-prefix-map={path}={mapped}"
                         for path, mapped in ((source, "/usr/src/owlbear"),
                                              (headers, "/usr/src/owlbear-headers"))
                         for kind in ("file", "debug", "macro"))
        make = ["make", "-B", "V=1", f"-j{args.jobs}", "CC=gcc", "CLANG=clang", f"KDIR={kdir}",
                f"BPFTOOL={args.bpftool}", f"VMLINUX_BTF={btf}",
                f"REPRO_CFLAGS={flags}", f"KCFLAGS={flags}", f"KAFLAGS={flags}",
                f"CFLAGS_EXTRA=-O2 -DNDEBUG {flags}"]
        # Skeletons precede daemon compilation, including under parallel make.
        subprocess.run(make + ["ebpf"], cwd=source, env=env, check=True)
        subprocess.run(["make", "-B", "V=1", f"-j{args.jobs}", "-C", str(headers),
                        "M=../source/kernel", "ARCH=arm64", "CC=gcc",
                        f"KCFLAGS={flags}", f"KAFLAGS={flags}", "modules"],
                       cwd=source, env=env, check=True)
        subprocess.run(make + ["daemon", "game", "cheats"], cwd=source, env=env, check=True)
        subprocess.run(make + ["test"], cwd=source, env=env, check=True)
        reported = json.loads(command([str(source / "daemon/owlbeard"), "--version"]))
        if reported != identity:
            raise ValueError("built daemon reports the wrong identity")
        for field, value in (("version", version), ("build_id", identity["build_id"]),
                             ("source_commit", commit)):
            if command(["modinfo", "-F", field, str(source / "kernel/owlbear.ko")]) != value:
                raise ValueError(f"kernel module reports the wrong {field}")
        vermagic = command(["modinfo", "-F", "vermagic", str(source / "kernel/owlbear.ko")])
        if vermagic.split()[0] != kernel:
            raise ValueError("kernel module vermagic disagrees with headers")
        (source / "build-inputs").mkdir()
        shutil.copyfile(btf, source / "build-inputs/vmlinux.btf")
        shutil.copyfile(kdir / ".config", source / "build-inputs/kernel.config")
        shutil.copyfile(kdir / "Module.symvers", source / "build-inputs/Module.symvers")
        files = {}
        for name in REQUIRED:
            data = (source / name).read_bytes()
            mode = 0o755 if name.endswith((".bin", ".so", ".sh")) or name in {
                "daemon/owlbeard", "game/owlbear-game"
            } else 0o644
            files[name] = (data, mode)
        manifest = {
            "schema": SCHEMA, "build": identity, "inputs": inputs,
            "kernel_vermagic": vermagic,
            "runtime": {
                "os": "Linux with the recorded userspace library versions",
                "kernel": "exact kernel release and compatible config/symbol versions; module is unsigned",
                "required_config": ["CONFIG_ARM64", "CONFIG_MODULES", "CONFIG_KPROBES",
                                    "CONFIG_BPF_SYSCALL", "CONFIG_BPF_LSM", "CONFIG_DEBUG_INFO_BTF"],
                "privileges": "root for module/eBPF loading and protected verification",
                "lsm": "bpf must be in /sys/kernel/security/lsm for BPF LSM enforcement",
                "qualification": "build and unit tests only; no live detection or enforcement claim",
            },
            "files": {name: {"sha256": digest(data), "size": len(data), "mode": mode}
                      for name, (data, mode) in sorted(files.items())},
        }
        check_payload(manifest, files)
        files["manifest.json"] = (encoded(manifest), 0o644)
        name = f"owlbear-{version}-linux-arm64-{kernel}-{identity['build_id'][:12]}"
        output.mkdir(parents=True)
        archive_path = output / f"{name}.tar.gz"
        write_archive(archive_path, name, files, epoch)
        verify(archive_path)
        (output / f"{name}.manifest.json").write_bytes(encoded(manifest))
        sums = "".join(f"{digest(item.read_bytes())}  {item.name}\n" for item in sorted(output.iterdir()))
        (output / "SHA256SUMS").write_text(sums)
        print(archive_path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    builder = commands.add_parser("build", help="build HEAD on native Ubuntu ARM64")
    builder.add_argument("--output", default="dist", help="new output directory (never overwritten)")
    builder.add_argument("--kdir", default=os.environ.get("KDIR", f"/lib/modules/{platform.release()}/build"))
    builder.add_argument("--btf", default=os.environ.get("VMLINUX_BTF", "/sys/kernel/btf/vmlinux"))
    builder.add_argument("--bpftool", default=os.environ.get("BPFTOOL", "bpftool"))
    builder.add_argument("--jobs", type=int, default=2)
    inspector = commands.add_parser("verify", help="verify archive or extracted installation without execution")
    inspector.add_argument("path")
    args = parser.parse_args()
    try:
        if args.command == "build":
            build(args)
        else:
            print(json.dumps(verify(args.path)["build"], sort_keys=True))
    except (OSError, ValueError, KeyError, tarfile.TarError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"artifact error: {error}\n")


if __name__ == "__main__":
    main()
