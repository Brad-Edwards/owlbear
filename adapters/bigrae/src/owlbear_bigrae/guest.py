"""Standard-library guest action, embedded in the SDK plan; never executed by planning."""
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import stat
import struct
import subprocess
import time


def command(args, timeout=20):
    return subprocess.check_output(args, text=True, timeout=timeout, stderr=subprocess.DEVNULL).strip()


def release_identity(config):
    root = Path(config["release"])
    if root.resolve(strict=True) != root or root.is_symlink():
        raise ValueError("release path must be canonical")
    for item in (root, *root.parents, *root.rglob("*")):
        info = item.lstat()
        if item.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("release and ancestors must be root-owned and not writable by others")
    raw = (root / "manifest.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != config["manifest_sha256"]:
        raise ValueError("manifest identity mismatch")
    manifest = json.loads(raw)
    # Authenticate the verifier before executing it. It then verifies the entire payload.
    verifier = root / "scripts/research-artifact.py"
    if verifier.is_symlink() or hashlib.sha256(verifier.read_bytes()).hexdigest() != manifest["files"]["scripts/research-artifact.py"]["sha256"]:
        raise ValueError("artifact verifier mismatch")
    identity = json.loads(command(["python3", str(verifier), "verify", str(root)], timeout=45))
    for key in ("build_id", "version", "source_commit", "kernel_release"):
        if identity[key] != config[key]:
            raise ValueError("release identity mismatch")
    if identity["architecture"] != "arm64" or platform.machine() != "aarch64" or platform.release() != config["kernel_release"]:
        raise ValueError("guest architecture or kernel mismatch")
    if json.loads(command([str(root / "daemon/owlbeard"), "--version"])) != identity:
        raise ValueError("daemon identity mismatch")
    return root, identity


def module_note_id(note):
    namesz, descsz, kind = struct.unpack_from("<III", note)
    offset = 12 + ((namesz + 3) & ~3)
    if kind != 3 or note[12:12+namesz] != b"GNU\0" or descsz == 0 or len(note) < offset + descsz:
        raise ValueError("invalid loaded module identity note")
    return note[offset:offset+descsz].hex()


def loaded_module_matches(root):
    # Compare the loaded GNU build note with the authenticated ELF module's note.
    build_id = module_note_id(Path("/sys/module/owlbear/notes/.note.gnu.build-id").read_bytes())
    expected = command(["readelf", "-n", str(root / "kernel/owlbear.ko")])
    if not any(line.strip() == "Build ID: " + build_id
               for line in expected.splitlines()):
        raise ValueError("loaded module differs from selected release")


def health(path):
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
        client.settimeout(2)
        client.connect(str(path))
        client.sendall(b"owlbear.control.v1 health")
        raw, _, flags, _ = client.recvmsg(8192)
        if flags & socket.MSG_TRUNC:
            raise ValueError("oversized health reply")
        return json.loads(raw)


def verify_health(state, config):
    mask = sum({"lsm": 1, "trace": 2, "kprobe": 4, "net": 8}[s] for s in config["sensors"])
    for key in ("ok", "ready", "kernel_responsive", "bpf_configured", "bpf_delivery",
                "code_integrity_baseline", "vdso_baseline", "signatures_loaded"):
        if state.get(key) is not True:
            raise ValueError("guest readiness condition not realized: " + key)
    for key in ("pid", "target_pid", "kernel_target_pid", "attached_bpf", "requested_bpf"):
        if type(state.get(key)) is not int:
            raise ValueError("invalid health integer: " + key)
    if state["pid"] <= 1:
        raise ValueError("invalid daemon PID")
    if (state.get("schema") != "owlbear.control.v1" or state.get("output_failed") is not False
            or state.get("target_pid") != config["target_pid"] or state.get("kernel_target_pid") != config["target_pid"]
            or state.get("attached_bpf") != mask or state.get("requested_bpf") != mask
            or state.get("kernel_enforce") is not config["enforce"]
            or state.get("requested_enforce") is not config["enforce"]
            or state.get("lsm_enforce") is not (config["enforce"] if mask & 1 else None)
            or type(state.get("kernel_dropped")) is not int or state["kernel_dropped"] != 0):
        raise ValueError("guest runtime configuration mismatch or known evidence loss")
    return state


def execute(payload):
    config = payload["configuration"]
    root, identity = release_identity(config)
    run_dir = Path("/run/owlbear-" + payload["operation"])
    configured = payload["phase"] == "configure"
    if configured:
        run_dir.mkdir(mode=0o700, exist_ok=True)
    permissions = run_dir.lstat()
    if not stat.S_ISDIR(permissions.st_mode) or permissions.st_uid != 0 or stat.S_IMODE(permissions.st_mode) != 0o700:
        raise ValueError("private root-owned runtime directory required")
    control = run_dir / "control.sock"
    if configured and not control.exists():
        if Path("/sys/module/owlbear").exists():
            loaded_module_matches(root)
        else:
            command(["insmod", str(root / "kernel/owlbear.ko"), f"target_pid={config['target_pid']}"])
        args = [str(root / "daemon/owlbeard"), "--target", str(config["target_pid"]),
                "--sensors", ",".join(config["sensors"]) or "none", "--control", str(control),
                "--events", str(run_dir / "events.jsonl"), "--sigs", str(root / "signatures/default.sigs")]
        if config["enforce"]:
            args.append("--enforce")
        with (run_dir / "daemon.log").open("xb") as log:
            subprocess.Popen(args, stdout=log, stderr=log, start_new_session=True, close_fds=True)
    loaded_module_matches(root)
    deadline = time.monotonic() + 15
    while True:
        try:
            state = verify_health(health(control), config)
            if Path(f"/proc/{state['pid']}/exe").resolve(strict=True) != root / "daemon/owlbeard":
                raise ValueError("running daemon identity mismatch")
            break
        except (OSError, ValueError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(.25)
    receipt = {"schema": "owlbear.bigrae.readiness/v1", "build": identity, "health": state}
    print(json.dumps(receipt, separators=(",", ":")))


def run(encoded):
    try:
        if os.geteuid() != 0:
            raise ValueError("root guest execution required")
        execute(json.loads(base64.b64decode(encoded, validate=True)))
    except (OSError, ValueError, KeyError, TypeError, struct.error, subprocess.SubprocessError):
        raise SystemExit("owlbear guest configuration/readback failed") from None
