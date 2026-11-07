# BigRAE GCP ARM64 qualification

The BigRAE-owned range qualification passed on 2026-11-07 UTC.
BigRAE realized the guest, executed the adapter, reported READY, and destroyed the range.
This record qualifies the exact candidate builds below for issue #34.
Raw evidence and tenant identifiers remain private and separate from study data.

## Selected inputs

| Input | Identity |
| --- | --- |
| Compute | `c4a-standard-2`, Google Axion, 2 vCPUs, 8 GiB, ARM64 |
| OS | Ubuntu 24.04 LTS |
| Kernel | `7.0.0-1017-gcp` |
| Owlbear version | `2.7.0` |
| Owlbear source | `8e2565800de9e9ea8956f04b8056abf0855a9fa9` |
| Build ID | `bc84789485be33c2ee21dcf475b7456bbb820c23ba88a24d5fd3c57ec1f1cc9e` |
| Artifact archive SHA-256 | `22ebb6627ff2ff85195330c89ea63d4166dd882f8923a578beccdf1d28688df8` |
| Release manifest SHA-256 | `74602eb2b277ab313a26c0a72551addb9d012751a5192fff6efc999ffdd0476c` |
| Adapter | `owlbear-bigrae-adapter` version `0.2.1` |
| Adapter build source | `db5bf425cfe82bb68da5ea401818d60429e436a1` |
| Worker registry manifest | `sha256:40c15b2c8e70631ea62814f4e12427dd0bf53d323e0517c2466e6649771cdc1f` |
| Adapter SDK | `bigrae-adapter-sdk` version `0.1.0`, pinned by `adapters/bigrae/sdk.json` |
| Qualification pack | `owlbear-arm64-qualification` version `0.1.1` |
| Pack content digest | `sha256:f495a76b3ddcb2e83fd168794bb8c36827772a72b2d7f925434d71ec8399007a` |
| Pack archive SHA-256 | `a4ec0e484b39e7900a20d450e46c7d54d3097bc6033e43e7fee822db6523512b` |
| BigRAE test source | `42d43f1ff8ac81d20527f0a36f7ab0960dfa7a57` |
| Signed deployer digest | `sha256:1e0d7d8fcab74ff3835af9c66669eb088c0f4e50965106463b97b98e3014e142` |
| Guest evidence archive SHA-256 | `8e3f612c062675606c7a33f730e6be1acc783b69445c0ee1227599752fd56028` |
| Private qualification index SHA-256 | `216c62550dbb697ac37473c75305f5dc535cca79cbea9e95a8a1f26982195b29` |

The [GCP release workflow](https://github.com/OpenRAE/bigrae/actions/runs/42414608854) passed its build, scan, and provenance checks.
The deployer verified the signatures, source revision, and running workload image digests.
The tenant's Linux deployment smoke also passed.

Provider readback confirmed the selected zone, gVNIC, NVMe, and a 40 GiB Hyperdisk Balanced boot disk.
The boot disk referenced the selected immutable ARM64 image.
The research guest explicitly disabled Secure Boot for the unsigned module.
The worker ran separately on AMD64 control-plane nodes.

## Observed results

The administrator binding retained every selected image and hardware field.
BigRAE executed both generated guest actions: configure and verify.
Both actions completed successfully before BigRAE reported the range READY.
The retained core receipts and logs bind those actions to the range operation.

The guest ran a fresh baseline before starting its protected target.
Both check processes ran outside the target's ancestry with root authority.
The protected checker explicitly verified `CAP_SYS_PTRACE`.
The adapter bound the protected PID and process start time to its operation.

| Independent check | Baseline result | Protected result |
| --- | --- | --- |
| `process_vm_readv` | 4 bytes, errno 0 | -1, `EPERM` |
| `process_vm_writev` | 4 bytes, errno 0 | -1, `EPERM` |
| `/proc/PID/mem` read | 4 bytes, errno 0 | -1, `EPERM` |
| `PTRACE_ATTACH` | 0, errno 0; detached normally | -1, `EPERM` |

Health remained ready after the protected checks and matched the pinned build identity.
Requested and attached BPF masks were both 15: LSM, trace, kprobe, and net.
Kernel enforcement and LSM enforcement were enabled.
Signature loading, code-integrity baseline, and vDSO baseline checks passed.
The kernel reported zero dropped events; BPF drop counts remained unknown.
The evidence includes BPF program/link inspection, privilege readback, and the loaded module's build note.
Every extracted evidence file matched its recorded SHA-256 value.

## Teardown

Flush and stop returned successful receipts.
The daemon exited, the caller-owned target stopped, and normal module unload succeeded.
BigRAE then destroyed the range through its normal credential-authorized lifecycle.
Its retained cleanup result was `verified_terminal`, with no residual obligations.

Independent GCP inventory confirmed absence of the owned VM, disk, address, firewall rules, subnet, and guest-key references.
The versioned image and worker remain available for reproduction.
Both temporary qualification credentials were revoked through the native API.

## Limits

`bpf_dropped: null` means BPF loss is unknown; zero known kernel drops does not establish lossless collection.
These checks cover four memory operations and the observed sensor/enforcement state.
They do not establish broader attack coverage or constitute paper study results.
Changes to the runtime build, kernel, or image require another qualification run.
