---
layout: default
title: Home
---

# Owlbear

ARM64 kernel-mode anti-cheat for Linux.

Hybrid architecture: kernel module for ARM64 hardware integrity checks + eBPF for process/memory monitoring. Userspace daemon consumes events from both, runs signature scans, ships telemetry to AWS (API Gateway + Lambda + DynamoDB).

## Components

| Component | Role |
|-----------|------|
| **Kernel module** (`owlbear.ko`) | ARM64 system register verification, debug register scanning, PAC key monitoring, VBAR integrity, kprobes on ptrace/memory access/module loads |
| **eBPF programs** | BPF LSM hooks (ptrace deny, /proc/mem deny, mmap monitor), syscall tracepoints (process_vm_readv/writev), kprobe (module load) |
| **Daemon** (`owlbeard`) | Event consumer from chardev + BPF ringbuf, policy engine, signature scanner, heartbeat tracker, telemetry client |
| **Platform** (AWS) | Lambda receiver, DynamoDB storage, API Gateway routing, S3 dashboard |

## Detection Coverage

Owlbear detects the following cheat techniques:

| Vector | Kernel Module | eBPF | Daemon |
|--------|:---:|:---:|:---:|
| `process_vm_readv/writev` | kprobe | syscall tracepoint | — |
| `/proc/pid/mem` | kprobe on `mem_open` | LSM `file_open` (-EPERM) | — |
| `ptrace` attach | kprobe on `__ptrace_may_access` | LSM (-EPERM) | — |
| PROT_EXEC mmap | kprobe on `vm_mmap_pgoff` | LSM `mmap_file` | — |
| Kernel module load | kprobe on `do_init_module` | BPF kprobe | — |
| HW debug registers | DBGBCR/DBGBVR periodic scan | — | — |
| System register tamper | SCTLR/TCR/MAIR/MDSCR verify | — | — |
| WXN disabled | SCTLR_EL1 bit 19 | — | — |
| PAC key substitution | APIAKey capture + verify | — | — |
| VBAR redirect | Vector table base compare | — | — |
| LD_PRELOAD | — | — | Function pointer integrity |
| Cheat binary in memory | — | — | Byte-pattern signatures |
| Behavioral anomalies | — | — | Event frequency thresholds |

## Pages

- [Architecture Overview](architecture/overview.html)
- [Process Monitoring](subsystems/process-monitoring.html)
- [Memory Protection](subsystems/memory-protection.html)
- [ARM64 Hardware Checks](subsystems/hardware-checks.html)
- [PAC, MTE, BTI](arm64/pac-mte-bti.html)
- [ARM64 vs x86](arm64/vs-x86.html)
