# Owlbear

ARM64 kernel-mode anti-cheat for Linux. Hybrid architecture: kernel module for ARM64 hardware checks (system registers, debug registers, PAC enable state) + eBPF for process/memory monitoring. Userspace daemon consumes events from both, runs signature scans, ships telemetry to AWS.

## Architecture

```
                              catalyst-dev (AWS)
                        +--------------------------+
                        |  API Gateway             |
                        |    |                     |
  Graviton c7g.large    |  Lambda (handler.py)     |
 +------------------+   |    |                     |
 | Game Process     |   |  DynamoDB (events)       |
 |   | heartbeat    |   |    |                     |
 |   v              |   |  S3 (artifacts)          |
 | Daemon ----------+-->|                          |
 |   |       HTTPS  |   +--------------------------+
 |   |              |
 |   +-- /dev/owlbear ------+
 |   |                      |
 |   +-- BPF ringbuf -------+
 |                          |
 | Kernel Module      eBPF  |
 | (ARM64 HW checks) (LSM) |
 +------------------+-------+
```

## Detection Matrix

| Technique | Detection | Component | Status |
|-----------|-----------|-----------|--------|
| `process_vm_readv` | Kprobe + BPF LSM + syscall tracepoint | Kernel + eBPF | Done |
| `/proc/pid/mem` | Kprobe + BPF LSM `file_open` | Kernel + eBPF | Done |
| `ptrace` attach | Kprobe + BPF LSM `ptrace_access_check` (-EPERM) | Kernel + eBPF | Done |
| PROT_EXEC mmap | Kprobe + BPF LSM `mmap_file` | Kernel + eBPF | Done |
| Kernel module load | Kprobe + BPF kprobe `do_init_module` | Kernel + eBPF | Done |
| `LD_PRELOAD` hook | Function pointer integrity check | Game + Daemon | Done |
| HW debug registers | ARM64 DBGBCR/DBGBVR 0-5, DBGWCR/DBGWVR 0-3 scan | Kernel | Done |
| System register tamper | SCTLR_EL1/TCR_EL1/MAIR_EL1/MDSCR_EL1 baseline + periodic verify | Kernel | Done |
| WXN disabled | SCTLR_EL1 bit 19 monitoring | Kernel | Done |
| PAC disabled | SCTLR_EL1.EnIA monitoring | Kernel | Done |
| VBAR_EL1 redirect | Vector table base comparison | Kernel | Done |
| Unknown kernel modules | Module list walk post-init | Kernel | Done |
| Cheat binary in memory | Byte-pattern signature scan (hex + wildcards) | Daemon | Done |
| Policy-based response | Event-type + severity → action mapping | Daemon | Done |
| Heartbeat anomalies | Frame count freeze/rewind + timeout detection | Daemon | Done |
| Code modification | `.text` section hash | Daemon | Planned |

## Structure

```
include/        Shared event header (kernel/eBPF/daemon contract)
kernel/         Loadable kernel module (C, Kbuild)
ebpf/           eBPF programs (C, libbpf CO-RE)
daemon/         Userspace daemon (C)
game/           Test game (C, ncurses)
cheats/         Test cheat programs (C)
platform/       Telemetry receiver (Python, Lambda + DynamoDB)
signatures/     Cheat signature database
deploy/         Terraform (catalyst-dev)
scripts/        Build, provisioning, demo, E2E verification
research/       Technical research (9 documents)
tests/          Unit and integration tests (57 tests, 5 suites)
```

## Why Hybrid

eBPF cannot access ARM64 system registers (`SCTLR_EL1`, `MDSCR_EL1`), debug registers (`DBGBCR`/`DBGBVR`), or PAC enable state. A kernel module can. eBPF provides safe, portable, verifier-checked monitoring via LSM hooks and tracepoints. The kernel module handles hardware-specific integrity checks.

## Building

```bash
sudo ./scripts/setup-dev.sh    # Install deps (detects arch)
make all                       # Build everything
make kernel                    # Kernel module
make test                      # Unit tests (57 across 5 suites)
```

Cross-compile from x86_64:
```bash
make all CROSS_COMPILE=aarch64-linux-gnu- CC=aarch64-linux-gnu-gcc
```

## ARM64 Features

| Feature | ARMv8 | Usage |
|---------|-------|-------|
| System Registers | Base | MMU/cache/WXN tamper detection |
| Debug Registers | Base | HW breakpoint detection on game code |
| PAC | v8.3+ | SCTLR_EL1.EnIA disable detection |
| BTI | v8.5+ | Branch target verification |
| MTE | v8.5+ | Documented only (requires HW) |

Target: c7g.large (Graviton3, PAC-capable).

## License

See [LICENSE](LICENSE).
