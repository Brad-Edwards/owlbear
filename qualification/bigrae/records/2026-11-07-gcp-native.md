# Native GCP compatibility check

The native compatibility check passed on 2026-11-07.
This record does not complete issue #34's BigRAE-owned range qualification.
Raw qualification evidence remains private and separate from study data.

## Selected inputs

| Input | Identity |
| --- | --- |
| Compute | C4A standard, 2 vCPUs, 8 GiB, native ARM64 |
| OS | Ubuntu 24.04 LTS |
| Kernel | `7.0.0-1017-gcp` |
| Owlbear source | `8e2565800de9e9ea8956f04b8056abf0855a9fa9` |
| Owlbear version | `2.7.0` |
| Build ID | `bc84789485be33c2ee21dcf475b7456bbb820c23ba88a24d5fd3c57ec1f1cc9e` |
| Artifact archive SHA-256 | `22ebb6627ff2ff85195330c89ea63d4166dd882f8923a578beccdf1d28688df8` |
| Release manifest SHA-256 | `74602eb2b277ab313a26c0a72551addb9d012751a5192fff6efc999ffdd0476c` |
| Adapter | `owlbear-bigrae-adapter` version `0.2.0` |
| Worker registry manifest | `sha256:6f5f6c55f3df4782cdcd06c233e48fee40fc4da9aad5ebfca3079a04bfa37ab0` |
| Evidence archive SHA-256 | `651a5b0a02048f25e8bd877c7679516c62ed55bd3df7cc0458c4dbf75c6e9fcf` |

The worker used AMD64 independently of the ARM64 guest.
Provider readback confirmed gVNIC, NVMe, vTPM, and integrity monitoring.
The selected research guest disabled Secure Boot to load the unsigned module.
The active LSM list included BPF; the checker had `CAP_SYS_PTRACE`.

## Observed results

Both check processes ran outside the target's ancestry with root authority.
The baseline workload exited before the protected workload started.
The adapter bound the protected PID and process start time to its operation.

| Check | Baseline result | Protected result |
| --- | --- | --- |
| `process_vm_readv` | 4 bytes, errno 0 | -1, `EPERM` |
| `process_vm_writev` | 4 bytes, errno 0 | -1, `EPERM` |
| `/proc/PID/mem` read | 4 bytes, errno 0 | -1, `EPERM` |
| `PTRACE_ATTACH` | 0, errno 0; detached normally | -1, `EPERM` |

The SDK-generated configure and verify actions completed successfully.
Health remained ready after the protected checks.
The requested and attached BPF masks were both 15: LSM, trace, kprobe, and net.
Kernel enforcement and LSM enforcement were enabled.
All initialization checks passed and the kernel reported zero dropped events.
BPF drop counts remained unknown, as represented by `bpf_dropped: null`.

Flush and stop returned successful receipts.
The daemon exited, the caller-owned target stopped, and normal module unload succeeded.
All retained evidence file hashes matched their recorded values.

## Remaining qualification

The tenant accepted the worker's isolated compatibility probe.
It also installed the qualification pack with passed conformance.
These results do not establish a realized BigRAE range.

Issue #34 still requires the signed test release, administrator image binding,
BigRAE-owned realization and adapter execution, evidence collection, and verified range destruction.
The native check covers the four memory operations above.
It does not establish broader attack coverage or produce paper study results.
