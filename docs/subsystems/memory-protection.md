---
layout: default
title: Memory Protection
---

# Memory Protection

## Attack Vectors

Linux provides three primary ways for a process to read another's memory:

1. **`/proc/<pid>/mem`** — file-based interface, requires same UID or `CAP_SYS_PTRACE`
2. **`process_vm_readv()` / `process_vm_writev()`** — syscall, no ptrace attachment needed
3. **`ptrace(PTRACE_PEEKDATA, ...)`** — debugger interface, word-at-a-time reads (covered in process monitoring)

All three must be monitored. A cheat only needs one to work.

## Kernel Module: Kprobes

### /proc/pid/mem

Kprobe on `mem_open` (fs/proc/base.c). Extracts the target PID from the proc inode via `get_proc_task()`. If the target is protected and the caller is not the game itself, emit `OWL_EVENT_PROC_MEM_ACCESS` (CRITICAL).

### process_vm_readv / process_vm_writev

Kprobes on `__arm64_sys_process_vm_readv` and `__arm64_sys_process_vm_writev`. The first syscall argument (target PID) is extracted from the pt_regs. On ARM64 kernel 6.1+, `__arm64_sys_*` wrappers pass user pt_regs directly — `regs->regs[0]` IS the first syscall arg (target PID), not a pointer to another pt_regs.

### PROT_EXEC mmap

Kprobe on `vm_mmap_pgoff`. Checks the 4th argument (prot flags) for `PROT_EXEC` (0x4). Only fires for the protected PID. Executable memory allocations in the game process are suspicious — normal game operation uses `mmap` with PROT_EXEC only at load time for shared libraries, not during runtime.

### Kernel Module Load

Kprobe on `do_init_module`. Reports any module loaded after owlbear. Kernel modules are the highest-privilege cheat vector on Linux — a cheat kmod can read any process's memory directly via `copy_from_user` or physical address mapping.

## eBPF: LSM Hooks

### file_open

```c
SEC("lsm/file_open")
int BPF_PROG(owl_file_open, struct file *file)
```

Walks the dentry chain: checks filename is "mem", parent is a PID directory, grandparent is "proc" or root. Parses PID from directory name. If protected and caller not whitelisted, returns `-EPERM`.

Path checking in BPF is limited — no `d_path()` equivalent. The dentry walk is a pragmatic solution that covers the `/proc/<pid>/mem` case without needing full path resolution.

### mmap_file

Monitors `PROT_EXEC` mappings in the protected process. Logs only (does not block) because executable mmaps are normal during library loading.

## Non-Fatal Registration

All kprobes register with non-fatal error handling. If a symbol isn't available on a particular kernel version, the remaining probes still activate. This handles kernel API changes across versions.
