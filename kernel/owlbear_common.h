/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * owlbear_common.h - Internal definitions shared across kernel module files
 *
 * This header is NOT shared with userspace. For the userspace-visible
 * interface, see include/owlbear_events.h.
 */

#ifndef OWLBEAR_COMMON_H
#define OWLBEAR_COMMON_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/ktime.h>
#include <linux/atomic.h>

#include "../include/owlbear_events.h"

/* -------------------------------------------------------------------------
 * Module-wide configuration
 * ----------------------------------------------------------------------- */

/*
 * Ring buffer for events flowing from kernel to userspace daemon.
 * Power-of-2 size for efficient masking.
 */
#define OWL_RING_SIZE_ORDER    12   /* 2^12 = 4096 events */
#define OWL_RING_SIZE          (1 << OWL_RING_SIZE_ORDER)
#define OWL_RING_MASK          (OWL_RING_SIZE - 1)

/* Maximum process name length in kernel (TASK_COMM_LEN) */
#define OWL_COMM_LEN           16

/* -------------------------------------------------------------------------
 * Event ring buffer
 *
 * Single-producer (kernel hooks), single-consumer (daemon reading from
 * chardev). We use a lock-free SPSC ring with atomic head/tail indices.
 * ----------------------------------------------------------------------- */

struct owl_ring {
	struct owlbear_event events[OWL_RING_SIZE];
	atomic_t             head;    /* Next write position (producer) */
	atomic_t             tail;    /* Next read position (consumer) */
	atomic_t             dropped; /* Events lost due to full ring */
};

/* -------------------------------------------------------------------------
 * Global module state
 *
 * Single instance — there is only one owlbear module loaded at a time.
 * All fields are protected as noted.
 * ----------------------------------------------------------------------- */

struct owl_state {
	/* Protection target — which PID are we guarding? */
	pid_t            target_pid;     /* Protected by target_lock */
	spinlock_t       target_lock;

	/* Enforcement mode: 0 = observe (log only), 1 = block + log */
	unsigned int     enforce;

	/* Event ring buffer */
	struct owl_ring  *ring;

	/* Wait queue — daemon blocks on read() until events are available */
	wait_queue_head_t wait_queue;

	/* Monotonic sequence counter for events */
	atomic_t         sequence;

	/* Total events generated since module load */
	atomic_t         events_total;

	/* Character device */
	int              major;          /* Dynamically allocated major number */
	struct class     *dev_class;
	struct device    *dev_device;

	/* Module initialized flag — set last in init, cleared first in exit */
	bool             initialized;
};

/* Global module state — defined in owlbear_main.c */
extern struct owl_state owl;

/* Ring buffer operations — defined in owlbear_main.c */
int ring_consume(struct owl_ring *ring, struct owlbear_event *event);
int ring_available(const struct owl_ring *ring);

/* -------------------------------------------------------------------------
 * Event submission API — used by all detection subsystems
 * ----------------------------------------------------------------------- */

/**
 * owl_emit_event - Submit an event to the ring buffer
 * @type:       Event type (enum owlbear_event_type)
 * @severity:   Event severity (enum owlbear_severity)
 * @pid:        PID of the process that triggered this event
 * @target_pid: PID of the protected process (may differ from @pid)
 * @comm:       Process name (TASK_COMM_LEN, may be NULL for current)
 *
 * Returns 0 on success, -ENOSPC if the ring buffer is full.
 * This function is safe to call from any context (interrupt, softirq, etc.)
 * as it uses only atomic operations and does not sleep.
 */
int owl_emit_event(u32 type, u32 severity, pid_t pid,
		   pid_t target_pid, const char *comm);

/**
 * owl_emit_event_full - Submit a fully populated event to the ring buffer
 * @event: Pointer to a complete event structure. The timestamp, sequence,
 *         and source fields will be overwritten.
 *
 * Returns 0 on success, -ENOSPC if the ring buffer is full.
 */
int owl_emit_event_full(struct owlbear_event *event);

/* -------------------------------------------------------------------------
 * Target PID helpers — thread-safe access
 * ----------------------------------------------------------------------- */

/**
 * owl_get_target_pid - Read the currently protected PID
 *
 * Returns the target PID, or 0 if no process is being protected.
 */
static inline pid_t owl_get_target_pid(void)
{
	pid_t pid;
	unsigned long flags;

	spin_lock_irqsave(&owl.target_lock, flags);
	pid = owl.target_pid;
	spin_unlock_irqrestore(&owl.target_lock, flags);

	return pid;
}

/**
 * owl_is_target - Check if a given PID is the protected process
 * @pid: PID to check
 *
 * Returns true if @pid matches the currently protected PID and a
 * target is actually set (i.e., target_pid != 0).
 */
static inline bool owl_is_target(pid_t pid)
{
	pid_t target = owl_get_target_pid();

	return target != 0 && target == pid;
}

/* -------------------------------------------------------------------------
 * Subsystem init/exit — called from owlbear_main.c
 * ----------------------------------------------------------------------- */

/* Character device (owlbear_chardev.c) */
int  owl_chardev_init(void);
void owl_chardev_exit(void);

/* Process monitoring (owlbear_process.c) */
int  owl_process_init(void);
void owl_process_exit(void);

/* Memory protection (owlbear_memory.c) */
int  owl_memory_init(void);
void owl_memory_exit(void);

/* Code integrity (owlbear_integrity.c) */
int  owl_integrity_init(void);
void owl_integrity_exit(void);

/* ARM64 hardware checks (owlbear_arm64.c) */
int  owl_arm64_init(void);
void owl_arm64_exit(void);

#endif /* OWLBEAR_COMMON_H */
