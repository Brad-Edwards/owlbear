---
layout: default
title: Process Monitoring
---

# Process Monitoring

## What It Detects

- Process creation, execution, and exit related to the protected game
- Ptrace attachment attempts (strace, gdb, cheat injectors)

## Kernel Module Implementation

### Tracepoints

Hooks `sched_process_fork`, `sched_process_exec`, `sched_process_exit` via kernel tracepoint API. Tracepoints are looked up dynamically with `for_each_kernel_tracepoint()` because direct symbol access isn't available to modules.

Fork and exec events are filtered: only emit if the process is related to the protected PID. Exit events for the protected PID itself are severity WARN (unexpected game termination).

### Ptrace Detection

Kprobe on `__ptrace_may_access`. On ARM64, the first argument (target task) is in `regs->regs[0]`. If the target is the protected PID and the caller is not whitelisted, emit a CRITICAL event.

The kprobe alone cannot deny the ptrace — it can only detect. For enforcement, the eBPF LSM hook returns -EPERM.

## eBPF Implementation

### LSM: ptrace_access_check

```c
SEC("lsm/ptrace_access_check")
int BPF_PROG(owl_ptrace_check, struct task_struct *child, unsigned int mode)
```

Reads `child->tgid` via `BPF_CORE_READ`, checks `protected_pids` map. If protected and caller not in `allowed_pids`, emits event and returns `-EPERM`. This is hard enforcement — the ptrace syscall fails.

### Tracepoint: sched_process_exec

Fires on every `execve()` when a target is set. The daemon filters relevance — logging all execs allows correlation of suspicious process launches near the game.

## Defense-in-Depth

Both the kprobe and BPF LSM hook cover ptrace. If the kernel module is unloaded, the eBPF hook still blocks. If eBPF programs are detached, the kprobe still detects. The daemon monitors for both removal scenarios.
