/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * bpf_loader.h - eBPF program loader and ring buffer interface
 *
 * Loads all three owlbear eBPF skeletons (LSM, tracepoint, kprobe),
 * populates BPF maps, and provides a ring buffer polling interface.
 * Graceful degradation: if any program fails to load, the others
 * still operate.
 */

#ifndef OWLBEAR_BPF_LOADER_H
#define OWLBEAR_BPF_LOADER_H

#include <stdbool.h>
#include <stdint.h>

#include "owlbear_events.h"

/* Opaque BPF context */
struct owl_bpf_ctx;

/*
 * Callback invoked for each BPF ring buffer event.
 * The caller converts the BPF event to a full owlbear_event.
 */
typedef void (*owl_bpf_event_cb)(const struct owlbear_event *ev, void *ctx);

/**
 * owl_bpf_init - Load and attach all eBPF programs
 * @cb:     Callback for ring buffer events (converted to owlbear_event)
 * @cb_ctx: Opaque context passed to callback
 *
 * Returns a BPF context on success (even partial — check has_* flags).
 * Returns NULL only on fatal allocation failure.
 */
struct owl_bpf_ctx *owl_bpf_init(owl_bpf_event_cb cb, void *cb_ctx);

/**
 * owl_bpf_destroy - Detach and unload all eBPF programs
 */
void owl_bpf_destroy(struct owl_bpf_ctx *ctx);

/**
 * owl_bpf_protect_pid - Add a PID to the protected_pids map
 * @ctx: BPF context
 * @pid: PID to protect
 *
 * Returns 0 on success, -1 on error.
 */
int owl_bpf_protect_pid(struct owl_bpf_ctx *ctx, uint32_t pid);

/**
 * owl_bpf_allow_pid - Add a PID to the allowed_pids map (whitelist)
 * @ctx: BPF context
 * @pid: PID to allow
 *
 * Returns 0 on success, -1 on error.
 */
int owl_bpf_allow_pid(struct owl_bpf_ctx *ctx, uint32_t pid);

/**
 * owl_bpf_ringbuf_fd - Get epoll-compatible fd for the ring buffer
 *
 * Returns fd >= 0, or -1 if ring buffer is not available.
 */
int owl_bpf_ringbuf_fd(const struct owl_bpf_ctx *ctx);

/**
 * owl_bpf_poll - Poll the ring buffer for events
 * @ctx:        BPF context
 * @timeout_ms: Timeout in milliseconds (-1 = block)
 *
 * Returns number of events consumed, or negative on error.
 */
int owl_bpf_poll(struct owl_bpf_ctx *ctx, int timeout_ms);

/**
 * owl_bpf_has_lsm - Check if LSM programs loaded successfully
 */
bool owl_bpf_has_lsm(const struct owl_bpf_ctx *ctx);

/**
 * owl_bpf_has_trace - Check if tracepoint programs loaded successfully
 */
bool owl_bpf_has_trace(const struct owl_bpf_ctx *ctx);

/**
 * owl_bpf_has_kprobe - Check if kprobe programs loaded successfully
 */
bool owl_bpf_has_kprobe(const struct owl_bpf_ctx *ctx);

/**
 * owl_bpf_event_convert - Convert a BPF ring buffer event to owlbear_event
 * @bpf_data:  Raw BPF event data (struct owl_bpf_event layout)
 * @bpf_size:  Size of BPF event data
 * @out:       Output owlbear_event
 *
 * Returns 0 on success, -1 if data is malformed.
 * This is a pure function — usable in tests without BPF.
 */
int owl_bpf_event_convert(const void *bpf_data, size_t bpf_size,
			   struct owlbear_event *out);

#endif /* OWLBEAR_BPF_LOADER_H */
