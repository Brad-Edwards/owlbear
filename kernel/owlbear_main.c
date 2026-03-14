// SPDX-License-Identifier: GPL-2.0-only
/*
 * owlbear_main.c - Module entry point and event ring buffer
 *
 * This is the top-level kernel module for the Owlbear ARM64 anti-cheat
 * prototype. It initializes all subsystems in dependency order and
 * provides the event ring buffer shared by all detection components.
 *
 * Initialization order:
 *   1. Ring buffer allocation
 *   2. Character device (/dev/owlbear)
 *   3. Process monitoring (tracepoints)
 *   4. Memory protection (kprobes)     [Phase 2]
 *   5. Integrity verification          [Phase 3]
 *   6. ARM64 hardware checks           [Phase 3]
 *
 * Teardown is reverse order. If any step fails during init, all
 * previously initialized subsystems are torn down cleanly.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/ktime.h>

#include "owlbear_common.h"

/* Module metadata */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Owlbear Project");
MODULE_DESCRIPTION("ARM64 anti-cheat kernel module prototype");
MODULE_VERSION("0.1.0");

/* Module parameters */
static int target_pid_param;
module_param_named(target_pid, target_pid_param, int, 0644);
MODULE_PARM_DESC(target_pid, "PID to protect (0 = none, set via ioctl)");

static int enforce_param;
module_param_named(enforce, enforce_param, int, 0644);
MODULE_PARM_DESC(enforce, "Enforcement mode (0 = observe, 1 = block)");

/* -------------------------------------------------------------------------
 * Global state — single instance
 * ----------------------------------------------------------------------- */

struct owl_state owl;

/* -------------------------------------------------------------------------
 * Ring buffer operations
 *
 * SPSC (single-producer, single-consumer) lock-free ring buffer.
 * Producer: any kernel hook context (may be interrupt/softirq)
 * Consumer: daemon reading via chardev (process context)
 *
 * The producer advances head, the consumer advances tail.
 * Buffer is full when (head + 1) & MASK == tail.
 * Buffer is empty when head == tail.
 * ----------------------------------------------------------------------- */

/**
 * ring_produce - Write an event into the ring buffer
 * @ring:  Ring buffer
 * @event: Event to copy into the ring
 *
 * Returns 0 on success, -ENOSPC if full.
 * Safe to call from any context (uses only atomics).
 */
static int ring_produce(struct owl_ring *ring,
			const struct owlbear_event *event)
{
	int head, next;

	head = atomic_read(&ring->head);
	next = (head + 1) & OWL_RING_MASK;

	if (next == atomic_read(&ring->tail)) {
		atomic_inc(&ring->dropped);
		return -ENOSPC;
	}

	memcpy(&ring->events[head], event, sizeof(*event));

	/*
	 * Write barrier: ensure the event data is visible before we
	 * advance the head pointer. The consumer must see consistent
	 * data when it observes the updated head.
	 */
	smp_wmb();
	atomic_set(&ring->head, next);

	return 0;
}

/**
 * ring_consume - Read an event from the ring buffer
 * @ring:  Ring buffer
 * @event: Output buffer for the event
 *
 * Returns 0 on success, -EAGAIN if empty.
 * Must be called from process context (chardev read).
 */
int ring_consume(struct owl_ring *ring, struct owlbear_event *event)
{
	int tail, head;

	tail = atomic_read(&ring->tail);
	head = atomic_read(&ring->head);

	if (tail == head)
		return -EAGAIN;

	/*
	 * Read barrier: ensure we read the event data after observing
	 * the head pointer update from the producer.
	 */
	smp_rmb();
	memcpy(event, &ring->events[tail], sizeof(*event));

	atomic_set(&ring->tail, (tail + 1) & OWL_RING_MASK);

	return 0;
}

/**
 * ring_available - Number of events available for reading
 */
int ring_available(const struct owl_ring *ring)
{
	int head = atomic_read(&ring->head);
	int tail = atomic_read(&ring->tail);

	return (head - tail) & OWL_RING_MASK;
}

/* -------------------------------------------------------------------------
 * Event emission API — used by all detection subsystems
 * ----------------------------------------------------------------------- */

int owl_emit_event(u32 type, u32 severity, pid_t pid,
		   pid_t target_pid, const char *comm)
{
	struct owlbear_event event = {};
	int ret;

	event.timestamp_ns = ktime_get_ns();
	event.event_type = type;
	event.severity = severity;
	event.source = OWL_SRC_KERNEL;
	event.pid = pid;
	event.target_pid = target_pid;
	event.sequence = (u32)atomic_inc_return(&owl.sequence);

	if (comm)
		strscpy(event.comm, comm, sizeof(event.comm));
	else if (current)
		strscpy(event.comm, current->comm, sizeof(event.comm));

	ret = ring_produce(owl.ring, &event);
	if (ret == 0) {
		atomic_inc(&owl.events_total);
		wake_up_interruptible(&owl.wait_queue);
	}

	return ret;
}

int owl_emit_event_full(struct owlbear_event *event)
{
	int ret;

	event->timestamp_ns = ktime_get_ns();
	event->source = OWL_SRC_KERNEL;
	event->sequence = (u32)atomic_inc_return(&owl.sequence);

	ret = ring_produce(owl.ring, event);
	if (ret == 0) {
		atomic_inc(&owl.events_total);
		wake_up_interruptible(&owl.wait_queue);
	}

	return ret;
}

/* -------------------------------------------------------------------------
 * Module initialization — ordered subsystem bring-up with rollback
 * ----------------------------------------------------------------------- */

static int __init owlbear_init(void)
{
	int ret;

	pr_info("owlbear: initializing (target_pid=%d, enforce=%d)\n",
		target_pid_param, enforce_param);

	/* Zero the global state */
	memset(&owl, 0, sizeof(owl));

	/* Initialize synchronization primitives */
	spin_lock_init(&owl.target_lock);
	init_waitqueue_head(&owl.wait_queue);
	atomic_set(&owl.sequence, 0);
	atomic_set(&owl.events_total, 0);

	/* Apply module parameters */
	owl.target_pid = (pid_t)target_pid_param;
	owl.enforce = enforce_param ? 1 : 0;

	/* Step 1: Allocate ring buffer */
	owl.ring = kzalloc(sizeof(*owl.ring), GFP_KERNEL);
	if (!owl.ring) {
		pr_err("owlbear: failed to allocate event ring buffer\n");
		return -ENOMEM;
	}
	atomic_set(&owl.ring->head, 0);
	atomic_set(&owl.ring->tail, 0);
	atomic_set(&owl.ring->dropped, 0);

	/* Step 2: Character device */
	ret = owl_chardev_init();
	if (ret) {
		pr_err("owlbear: chardev init failed: %d\n", ret);
		goto err_ring;
	}

	/* Step 3: Process monitoring */
	ret = owl_process_init();
	if (ret) {
		pr_err("owlbear: process monitor init failed: %d\n", ret);
		goto err_chardev;
	}

	/* Step 4: Memory protection */
	ret = owl_memory_init();
	if (ret) {
		pr_err("owlbear: memory protection init failed: %d\n", ret);
		goto err_process;
	}

	/* Step 5: Integrity verification */
	ret = owl_integrity_init();
	if (ret) {
		pr_err("owlbear: integrity init failed: %d\n", ret);
		goto err_memory;
	}

	/* Step 6: ARM64 hardware checks */
	ret = owl_arm64_init();
	if (ret) {
		pr_err("owlbear: ARM64 init failed: %d\n", ret);
		goto err_integrity;
	}

	owl.initialized = true;
	pr_info("owlbear: initialized successfully\n");

	return 0;

err_integrity:
	owl_integrity_exit();
err_memory:
	owl_memory_exit();
err_process:
	owl_process_exit();
err_chardev:
	owl_chardev_exit();
err_ring:
	kfree(owl.ring);
	owl.ring = NULL;
	return ret;
}

static void __exit owlbear_exit(void)
{
	pr_info("owlbear: shutting down\n");

	owl.initialized = false;

	/* Reverse order of init */
	owl_arm64_exit();
	owl_integrity_exit();
	owl_memory_exit();
	owl_process_exit();
	owl_chardev_exit();

	/* Report statistics */
	if (owl.ring) {
		int dropped = atomic_read(&owl.ring->dropped);
		int total = atomic_read(&owl.events_total);

		pr_info("owlbear: stats: %d events generated, %d dropped\n",
			total, dropped);
		kfree(owl.ring);
		owl.ring = NULL;
	}

	pr_info("owlbear: unloaded\n");
}

module_init(owlbear_init);
module_exit(owlbear_exit);
