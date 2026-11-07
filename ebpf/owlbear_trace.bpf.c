// SPDX-License-Identifier: GPL-2.0-only
/*
 * owlbear_trace.bpf.c - Tracepoint and syscall monitoring
 *
 * Tracepoints:
 *   sched/sched_process_exec  - log execve() calls
 *
 * Syscall tracepoints:
 *   syscalls/sys_enter_process_vm_readv   - cross-process read detection
 *   syscalls/sys_enter_process_vm_writev  - cross-process write detection
 */

#include "owlbear_common.bpf.h"

SEC("tracepoint/sched/sched_process_exec")
int owl_trace_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	struct owl_bpf_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev)
		return 0;
	__builtin_memset(ev, 0, sizeof(*ev));
	ev->timestamp_ns = bpf_ktime_get_ns();
	ev->event_type = OWL_EVENT_PROCESS_EXEC;
	ev->severity = OWL_SEV_INFO;
	ev->pid = pid;
	bpf_get_current_comm(ev->comm, sizeof(ev->comm));
	/* detail: parent PID (4), UID (4), terminated executable path (40). */
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u32 parent = BPF_CORE_READ(task, real_parent, tgid);
	__u32 uid = bpf_get_current_uid_gid();
	__builtin_memcpy(ev->detail, &parent, sizeof(parent));
	__builtin_memcpy(ev->detail + 4, &uid, sizeof(uid));
	__u32 offset = ctx->__data_loc_filename & 0xffff;
	bpf_probe_read_kernel_str(ev->detail + 8, 40, (const char *)ctx + offset);
	bpf_ringbuf_submit(ev, 0);
	__u32 zero = 0;
	__u64 *count = bpf_map_lookup_elem(&event_count, &zero);
	if (count)
		__sync_fetch_and_add(count, 1);

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_vm_readv")
int owl_trace_vm_readv(struct trace_event_raw_sys_enter *ctx)
{
	__u32 target_pid = (__u32)ctx->args[0];
	__u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

	if (!is_protected(target_pid))
		return 0;

	if (is_allowed(caller_pid) || caller_pid == target_pid)
		return 0;

	emit_event(OWL_EVENT_VM_READV_ATTEMPT, OWL_SEV_CRITICAL,
		   caller_pid, target_pid,
		   "BPF: process_vm_readv detected");

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_vm_writev")
int owl_trace_vm_writev(struct trace_event_raw_sys_enter *ctx)
{
	__u32 target_pid = (__u32)ctx->args[0];
	__u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

	if (!is_protected(target_pid))
		return 0;

	if (is_allowed(caller_pid) || caller_pid == target_pid)
		return 0;

	emit_event(OWL_EVENT_VM_WRITEV_ATTEMPT, OWL_SEV_CRITICAL,
		   caller_pid, target_pid,
		   "BPF: process_vm_writev detected");

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
