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

	emit_event(OWL_EVENT_PROCESS_EXEC, OWL_SEV_INFO,
		   pid, 0, "BPF: process exec");

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
