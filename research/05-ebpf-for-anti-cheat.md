# eBPF for Anti-Cheat: Modern Linux Monitoring

## Why eBPF Matters for ARM64 Anti-Cheat

eBPF is the most viable approach for production-quality anti-cheat monitoring on modern Linux (including ARM64):
- No kernel module signing issues (BPF programs are verified by the kernel verifier)
- No kernel ABI dependency (BPF CO-RE: Compile Once, Run Everywhere)
- Cannot crash the kernel (verifier guarantees safety)
- Already used by major security products (Falco, Tetragon, Tracee)
- Full ARM64 support with JIT compilation

Trade-off: eBPF programs have constraints (bounded loops, limited stack, restricted memory access) that traditional kernel modules do not.

## eBPF Program Types Relevant to Anti-Cheat

### 1. BPF_PROG_TYPE_LSM (LSM hooks)
Attach BPF programs to Linux Security Module hooks:

```c
SEC("lsm/ptrace_access_check")
int BPF_PROG(restrict_ptrace, struct task_struct *child, unsigned int mode) {
    u32 child_pid = BPF_CORE_READ(child, tgid);
    u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

    u32 *protected = bpf_map_lookup_elem(&protected_pids, &child_pid);
    if (!protected)
        return 0;

    u32 *allowed = bpf_map_lookup_elem(&allowed_pids, &caller_pid);
    if (allowed)
        return 0;

    struct event_t event = {
        .type = EVENT_PTRACE_BLOCKED,
        .pid = caller_pid,
        .target_pid = child_pid,
    };
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return -EPERM;
}
```

Available LSM hooks for anti-cheat:
```
ptrace_access_check    - block debugger attachment
bprm_check_security    - control what binaries can execute
mmap_file              - monitor memory-mapped file operations
file_open              - control file access (/proc/pid/mem)
task_alloc             - monitor new task (process/thread) creation
socket_connect         - monitor network connections
kernel_read_file       - monitor kernel module loading
```

### 2. BPF_PROG_TYPE_TRACEPOINT
Attach to kernel tracepoints for process/memory monitoring:

```c
SEC("tracepoint/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec *ctx) {
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(comm, sizeof(comm));

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct exec_event_t event = {
        .pid = pid,
        .ppid = BPF_CORE_READ(
            (struct task_struct *)bpf_get_current_task(), real_parent, tgid),
    };
    bpf_probe_read_str(event.comm, sizeof(event.comm), comm);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_vm_readv")
int trace_vm_readv(struct trace_event_raw_sys_enter *ctx) {
    pid_t target_pid = (pid_t)ctx->args[0];

    u32 *protected = bpf_map_lookup_elem(&protected_pids, &target_pid);
    if (protected) {
        u32 caller = bpf_get_current_pid_tgid() >> 32;
        struct event_t event = {
            .type = EVENT_VM_READV_ATTEMPT,
            .pid = caller,
            .target_pid = target_pid,
        };
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                             &event, sizeof(event));
    }
    return 0;
}
```

### 3. BPF_PROG_TYPE_KPROBE
Dynamic instrumentation of kernel functions:

```c
SEC("kprobe/load_module")
int kprobe_load_module(struct pt_regs *ctx) {
    struct module_event_t event = {
        .type = EVENT_MODULE_LOAD,
        .pid = bpf_get_current_pid_tgid() >> 32,
    };
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                         &event, sizeof(event));
    return 0;
}

SEC("kprobe/__vm_mmap_locked")
int kprobe_mmap(struct pt_regs *ctx) {
    unsigned long prot = PT_REGS_PARM4_CORE(ctx);

    if (prot & 0x4) {  // PROT_EXEC
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        u32 *protected = bpf_map_lookup_elem(&protected_pids, &pid);
        if (protected) {
            struct event_t event = {
                .type = EVENT_EXEC_MMAP,
                .pid = pid,
            };
            bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                                 &event, sizeof(event));
        }
    }
    return 0;
}
```

### 4. BPF_PROG_TYPE_RAW_TRACEPOINT
Lower overhead than regular tracepoints:

```c
SEC("raw_tracepoint/sched_switch")
int raw_tp_sched_switch(struct bpf_raw_tracepoint_args *ctx) {
    struct task_struct *next = (struct task_struct *)ctx->args[2];
    u32 next_pid = BPF_CORE_READ(next, tgid);
    return 0;
}
```

## BPF Maps for State Management

```c
// Protected process PIDs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, u32);
    __type(value, u32);
} protected_pids SEC(".maps");

// Whitelisted processes
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, u32);
    __type(value, u32);
} allowed_pids SEC(".maps");

// Ring buffer for events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);  // 1MB
} events SEC(".maps");

// Per-CPU hash for tracking memory access patterns
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 4096);
    __type(key, u64);
    __type(value, struct access_record);
} memory_access_tracking SEC(".maps");

// LRU hash for signature cache
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct region_key);
    __type(value, struct scan_result);
} scan_cache SEC(".maps");
```

## BPF CO-RE for ARM64 Portability

BPF CO-RE (Compile Once, Run Everywhere) is critical for ARM64 where kernel versions vary widely:

```c
u32 pid = BPF_CORE_READ(task, tgid);
u32 ppid = BPF_CORE_READ(task, real_parent, tgid);

if (bpf_core_field_exists(task->loginuid)) {
    u32 loginuid = BPF_CORE_READ(task, loginuid.val);
}
```

## Cilium Tetragon as Foundation

Tetragon provides a production-ready eBPF security framework that could serve as the foundation for an eBPF-based anti-cheat:

Key capabilities:
- Process lifecycle monitoring with full cgroup/namespace awareness
- File access monitoring with path resolution
- Network monitoring with connection tracking
- Configurable enforcement policies (observe or block)
- Efficient in-kernel filtering (only events matching policy generate userspace events)

Architecture:
```
[Tetragon Agent (userspace)]
    |
    | BPF maps (config + events)
    |
[BPF Programs in kernel]
    |--- kprobes on syscalls
    |--- LSM hooks
    |--- tracepoints
    |--- cgroup hooks
```

## Limitations of eBPF for Anti-Cheat

1. **No arbitrary kernel memory access**: BPF programs can only read memory through helper functions. Cannot walk arbitrary data structures or directly hash kernel code sections.

2. **No direct hardware register access**: cannot read ARM64 system registers (SCTLR_EL1, debug registers). Must use kprobes on functions that access these, or a companion kernel module.

3. **Verifier constraints**: bounded loop iterations, 512-byte stack limit, cannot call arbitrary kernel functions (only BPF helpers), program size limited (1M instructions on modern kernels).

4. **No persistent kernel state modification**: BPF programs cannot modify kernel code or data structures. Good for monitoring, but cannot actively protect (cannot strip handle permissions). LSM hooks CAN deny operations (return -EPERM), which provides enforcement.

5. **BPF programs can be detached by root**: a cheat with root access can unload BPF programs. Must monitor for BPF program detachment and complement with kernel module for tamper resistance.

## Recommended Hybrid Architecture

For a production anti-cheat on ARM64 Linux:

```
+-----------------------------------------------+
|  Userspace Anti-Cheat Service                  |
|  - Event processing from BPF ring buffer       |
|  - Signature scanning (Yara rules)             |
|  - Statistical analysis                        |
|  - Server communication (heartbeat/telemetry)  |
+-----------------------------------------------+
         |                           |
    BPF maps/ringbuf            chardev/ioctl
         |                           |
+-------------------+    +---------------------+
| eBPF Programs     |    | Kernel Module       |
| - LSM hooks       |    | - System reg checks |
| - Tracepoints     |    | - Debug reg monitor |
| - Kprobes         |    | - Code integrity    |
| - Process monitor |    | - PAC verification  |
+-------------------+    | - Memory protection |
                         | - Self-integrity    |
                         +---------------------+
```

eBPF handles the broad monitoring (what processes are doing, what files they access, what memory operations they perform). The kernel module handles ARM64-specific hardware checks that eBPF cannot perform (system registers, debug registers, PAC keys, TrustZone interaction).
