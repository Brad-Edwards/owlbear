# ARM64 research artifacts

An artifact is a fixed build for an experiment to pin. It is not an experiment
result. Building, inspecting and extracting it do not load modules, run attacks,
collect research data, or modify a study dataset.

## Build

Use Ubuntu 24.04 ARM64 with GCC, Clang, LLVM, libbpf, libelf, zlib, OpenSSL,
libcurl and ncurses development packages, kmod, bpftool and configured ARM64
kernel headers. The GitHub `Research artifact` workflow installs these without
using AWS or GCP. It builds twice in separate temporary trees and requires
identical archive and manifest checksums.

```sh
KDIR=/usr/src/linux-headers-<exact-release> \
BPFTOOL=/usr/lib/linux-tools/<version>/bpftool make artifact
```

Only **HEAD's committed sources** are built. Uncommitted changes are not included.
Tracked binaries are rebuilt. `dist/` must not already exist: the build refuses
to overwrite output. The original checkout and any research data remain untouched.

The archive contains the daemon, game, kernel module, four eBPF objects, twelve
attack fixtures, two preload libraries, default signatures, verifier, license,
this guide, and build inputs. It preserves the repository's relative paths.

The manifest records:

- Version from `VERSION`, full source commit, source timestamp, and build ID.
- OS, installed package versions, toolchain versions, kernel release and vermagic.
- Hashes of the kernel config, symbol versions and BTF input; copies are included.
- Every payload file's SHA-256, size and permissions.
- Runtime assumptions and the limits of build verification.

The build ID hashes the recorded build identity and inputs. Payload checksums
identify the actual output bytes. `owlbeard --version` prints the embedded build
identity as JSON without needing root or opening the kernel device. The kernel
module reports `version`, `source_commit` and `build_id` through `modinfo -F`.
Ordinary development builds explicitly report an unrecorded development identity.
The existing numeric kernel ioctl version remains a separate interface version.

## Verify and install

Download `SHA256SUMS`, the archive and the matching external manifest from the
same release. Verify the outer checksums **before extraction**, then verify all
payload files. An extracted installation can be checked again before every run:

```sh
sha256sum --check SHA256SUMS
python3 scripts/research-artifact.py verify owlbear-<identity>.tar.gz
mkdir /path/to/new-installation
tar -xzf owlbear-<identity>.tar.gz -C /path/to/new-installation --strip-components=1
python3 /path/to/new-installation/scripts/research-artifact.py verify /path/to/new-installation
/path/to/new-installation/daemon/owlbeard --version
```

Inspection checks hashes, completeness, permissions and ELF architectures without
executing the payload. Do not mix files from different artifacts. Keep each run's
manifest, archive checksum and reported daemon identity with its evidence.
Checksums detect changed bytes; they do not authenticate an untrusted publisher.

## Runtime limits and rebuilding

The unsigned module requires the recorded ARM64 kernel release, compatible
configuration and symbol versions, and a host policy that permits loading it.
Installing an arbitrary ARM64 kernel is insufficient. Kernel modules, kprobes,
BPF syscalls, BPF LSM and BTF must be available; `bpf` must be active in
`/sys/kernel/security/lsm` for BPF LSM enforcement. Loading requires root.
Userspace dynamic libraries must be compatible with the recorded build versions.
PAC and other hardware checks depend on the target CPU's capabilities.

The build pins its source and records its external inputs. To reproduce it, use
the same commit, kernel headers, OS packages and toolchain versions. Pass the
included `build-inputs/vmlinux.btf` with `--btf` to reuse the exact BTF input.
The workflow's runner and package repositories can change over time: a future
build with newer inputs is a **different build**, not evidence of a matching
artifact. Preserve the release archive; package versions alone do not guarantee
that upstream repositories will retain all dependencies.

Build and unit-test success do not prove runtime readiness, complete sensor
coverage or attack blocking. Live BigRAE qualification belongs to issues #33–34;
study execution and resulting data belong to the individual paper repositories.

## Release

After review and merge, a maintainer tags the commit `v< VERSION >` (without
spaces). The workflow requires the tag to match `VERSION` and be reachable from
`main`. Successful builds attach the archive, manifest and checksums to a draft
GitHub release for maintainer publication. Existing releases are not overwritten.
PR builds publish CI artifacts only. No tag or release is needed to review a PR.

The reproducibility controls follow the Linux kernel's
[reproducible build guidance](https://docs.kernel.org/kbuild/reproducible-builds.html).
