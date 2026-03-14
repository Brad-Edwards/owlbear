// SPDX-License-Identifier: GPL-2.0-only
/*
 * bpf_event_convert.c - BPF event conversion (no BPF dependencies)
 *
 * Extracted from bpf_loader.c so tests can link without libbpf.
 * This file contains only the pure owl_bpf_event_convert() function.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "bpf_loader.h"

/*
 * BPF event structure — must match owlbear_common.bpf.h.
 */
struct owl_bpf_event_layout {
	uint64_t timestamp_ns;
	uint32_t event_type;
	uint32_t severity;
	uint32_t pid;
	uint32_t target_pid;
	char     comm[16];
	char     detail[48];
};

int owl_bpf_event_convert(const void *bpf_data, size_t bpf_size,
			   struct owlbear_event *out)
{
	if (!bpf_data || !out)
		return -1;

	if (bpf_size < sizeof(struct owl_bpf_event_layout))
		return -1;

	const struct owl_bpf_event_layout *bev = bpf_data;

	memset(out, 0, sizeof(*out));
	out->timestamp_ns = bev->timestamp_ns;
	out->event_type = bev->event_type;
	out->severity = bev->severity;
	out->source = OWL_SRC_EBPF;
	out->pid = bev->pid;
	out->target_pid = bev->target_pid;
	memcpy(out->comm, bev->comm, sizeof(out->comm));

	switch (bev->event_type) {
	case OWL_EVENT_PTRACE_ATTEMPT:
	case OWL_EVENT_PROC_MEM_ACCESS:
	case OWL_EVENT_VM_READV_ATTEMPT:
	case OWL_EVENT_VM_WRITEV_ATTEMPT:
	case OWL_EVENT_MPROTECT_EXEC:
		out->payload.memory.caller_pid = bev->pid;
		memcpy(out->payload.memory.caller_comm, bev->comm,
		       sizeof(out->payload.memory.caller_comm) < sizeof(bev->comm)
		       ? sizeof(out->payload.memory.caller_comm)
		       : sizeof(bev->comm));
		break;

	case OWL_EVENT_MODULE_LOAD:
		memcpy(out->payload.module.name, bev->detail,
		       sizeof(out->payload.module.name) < sizeof(bev->detail)
		       ? sizeof(out->payload.module.name)
		       : sizeof(bev->detail));
		break;

	default:
		memcpy(out->payload.raw, bev->detail,
		       sizeof(out->payload.raw) < sizeof(bev->detail)
		       ? sizeof(out->payload.raw)
		       : sizeof(bev->detail));
		break;
	}

	return 0;
}
