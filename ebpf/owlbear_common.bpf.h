/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * owlbear_common.bpf.h - Shared definitions for eBPF programs
 *
 * Defines BPF maps and event structures used across all owlbear
 * eBPF programs. Kept separate from the kernel module's headers
 * because BPF programs use vmlinux.h types, not linux/types.h.
 */

#ifndef OWLBEAR_COMMON_BPF_H
#define OWLBEAR_COMMON_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

/* -------------------------------------------------------------------------
 * Event types — must match include/owlbear_events.h
 * Duplicated here because BPF programs can't include userspace headers.
 * ----------------------------------------------------------------------- */

#define OWL_EVENT_PROCESS_EXEC       0x0003
#define OWL_EVENT_PTRACE_ATTEMPT     0x0100
#define OWL_EVENT_PROC_MEM_ACCESS    0x0101
#define OWL_EVENT_VM_READV_ATTEMPT   0x0102
#define OWL_EVENT_VM_WRITEV_ATTEMPT  0x0103
#define OWL_EVENT_EXEC_MMAP          0x0104
#define OWL_EVENT_MODULE_LOAD        0x0200

#define OWL_SEV_INFO     0
#define OWL_SEV_WARN     1
#define OWL_SEV_CRITICAL 2

#define OWL_SRC_EBPF     1

/* -------------------------------------------------------------------------
 * BPF event structure
 *
 * Simplified version of struct owlbear_event for the BPF ring buffer.
 * We keep it smaller than the full 128-byte struct because BPF stack
 * is limited to 512 bytes. The daemon maps this to the full struct.
 * ----------------------------------------------------------------------- */

struct owl_bpf_event {
	__u64 timestamp_ns;
	__u32 event_type;
	__u32 severity;
	__u32 pid;            /* Process that caused this */
	__u32 target_pid;     /* Protected process */
	char  comm[16];       /* Process name */
	char  detail[48];     /* Event-specific detail string */
};

/* -------------------------------------------------------------------------
 * BPF Maps — shared across all owlbear BPF programs
 * ----------------------------------------------------------------------- */

/* Protected PIDs — daemon populates this when game registers */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);     /* PID */
	__type(value, __u32);   /* flags (reserved, currently unused) */
} protected_pids SEC(".maps");

/* Allowed PIDs — whitelist (daemon, game itself) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u32);     /* PID */
	__type(value, __u32);   /* permission level */
} allowed_pids SEC(".maps");

/* Ring buffer for events to userspace daemon */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);  /* 1 MB */
} events SEC(".maps");

/* Per-CPU event count for rate limiting */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} event_count SEC(".maps");

/* -------------------------------------------------------------------------
 * Helper: check if a PID is protected
 * ----------------------------------------------------------------------- */

static __always_inline bool is_protected(__u32 pid)
{
	return bpf_map_lookup_elem(&protected_pids, &pid) != NULL;
}

/* -------------------------------------------------------------------------
 * Helper: check if a PID is whitelisted (allowed)
 * ----------------------------------------------------------------------- */

static __always_inline bool is_allowed(__u32 pid)
{
	return bpf_map_lookup_elem(&allowed_pids, &pid) != NULL;
}

/* -------------------------------------------------------------------------
 * Helper: emit an event to the ring buffer
 * ----------------------------------------------------------------------- */

static __always_inline int emit_event(__u32 type, __u32 severity,
				      __u32 pid, __u32 target_pid,
				      const char *detail)
{
	struct owl_bpf_event *ev;

	ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev)
		return -1;

	ev->timestamp_ns = bpf_ktime_get_ns();
	ev->event_type = type;
	ev->severity = severity;
	ev->pid = pid;
	ev->target_pid = target_pid;
	bpf_get_current_comm(ev->comm, sizeof(ev->comm));

	if (detail)
		__builtin_memcpy(ev->detail, detail, sizeof(ev->detail));

	bpf_ringbuf_submit(ev, 0);

	/* Increment event counter */
	__u32 zero = 0;
	__u64 *count = bpf_map_lookup_elem(&event_count, &zero);
	if (count)
		__sync_fetch_and_add(count, 1);

	return 0;
}

#endif /* OWLBEAR_COMMON_BPF_H */
