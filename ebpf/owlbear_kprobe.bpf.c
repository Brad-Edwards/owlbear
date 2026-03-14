// SPDX-License-Identifier: GPL-2.0-only
/*
 * owlbear_kprobe.bpf.c - Kprobe-based monitoring
 *
 * Kprobes on internal kernel functions for detection where tracepoints
 * are not available. These complement the kernel module's kprobes —
 * having both provides defense-in-depth (disabling one doesn't
 * disable the other).
 *
 * Kprobes:
 *   do_init_module  - kernel module loading
 */

#include "owlbear_common.bpf.h"

/* -------------------------------------------------------------------------
 * Kprobe: do_init_module
 *
 * Fires when a kernel module completes initialization. Any module
 * loading while the game is running is suspicious — cheat kernel
 * modules are a primary attack vector.
 * ----------------------------------------------------------------------- */

SEC("kprobe/do_init_module")
int BPF_KPROBE(owl_kprobe_module_load, struct module *mod)
{
	char name[48] = {};
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	bpf_probe_read_kernel_str(name, sizeof(name),
				  &mod->name);

	/* Use the detail field to pass the module name */
	struct owl_bpf_event *ev;

	ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev)
		return 0;

	ev->timestamp_ns = bpf_ktime_get_ns();
	ev->event_type = OWL_EVENT_MODULE_LOAD;
	ev->severity = OWL_SEV_WARN;
	ev->pid = pid;
	ev->target_pid = 0;
	bpf_get_current_comm(ev->comm, sizeof(ev->comm));
	__builtin_memcpy(ev->detail, name, sizeof(ev->detail));

	bpf_ringbuf_submit(ev, 0);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
