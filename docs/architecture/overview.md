---
layout: default
title: Architecture
---

# Architecture

## Data Flow

```
Game Process
  |
  | heartbeat (Unix socket, 2s interval)
  v
Daemon (owlbeard)
  |                          |
  | /dev/owlbear (chardev)   | BPF ringbuf
  | blocking read + ioctl    | event consumer
  v                          v
Kernel Module              eBPF Programs
  |                          |
  |-- process tracepoints    |-- LSM hooks (deny + log)
  |-- memory kprobes         |-- syscall tracepoints
  |-- ARM64 HW checks        |-- kprobe (module load)
  |-- module enumeration     |
  |                          |
  +-- periodic workqueue     +-- BPF maps
      (sysreg verify, 5s)       (protected_pids, allowed_pids)
```

Daemon merges events from both sources, evaluates the policy engine, runs signature scans, and ships telemetry to the platform.

## Why Two Kernel Components

eBPF and the kernel module serve different purposes:

**eBPF programs:**
- Safe (kernel verifier rejects invalid programs)
- Portable (CO-RE: Compile Once, Run Everywhere)
- Can enforce via LSM hooks (return -EPERM)
- Cannot access ARM64 system registers
- Can be updated without module reload

**Kernel module:**
- Full hardware access (MRS/MSR for system registers)
- Can read debug registers (DBGBCR, DBGBVR, DBGWCR, DBGWVR)
- Can read PAC keys (APIAKeyHi/Lo_EL1)
- Can verify VBAR_EL1 (exception vector table)
- Runs periodic workqueue for integrity checks
- Provides chardev for daemon communication

Disabling one doesn't disable the other. The daemon detects if either component is removed.

## Event Pipeline

1. Detection occurs in kernel module or eBPF program
2. Event written to ring buffer (SPSC lock-free for kmod, BPF ringbuf for eBPF)
3. Daemon consumes via blocking read (kmod) or ringbuf callback (eBPF)
4. Policy engine evaluates: OBSERVE / LOG / BLOCK / KILL
5. Event logged locally (structured text)
6. Events batched and shipped to platform via HTTPS (15s flush interval)
7. Platform stores in DynamoDB, returns action to daemon

## Communication

| Path | Mechanism | Direction |
|------|-----------|-----------|
| Kernel → Daemon | `/dev/owlbear` chardev, blocking read | Events |
| Daemon → Kernel | ioctl (SET_TARGET, SET_MODE, GET_STATUS) | Control |
| eBPF → Daemon | BPF ringbuf (1MB) | Events |
| Daemon → eBPF | BPF map updates (protected_pids, allowed_pids) | Config |
| Game → Daemon | Unix socket heartbeat | Liveness |
| Daemon → Platform | HTTPS POST /events, POST /heartbeat | Telemetry |
| Platform → Daemon | HTTPS response body | Actions (continue/kill) |
