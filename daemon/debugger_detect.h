/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * debugger_detect.h - TracerPid polling for debugger detection
 *
 * Complements eBPF LSM ptrace hooks by polling /proc/<pid>/status
 * for a non-zero TracerPid. Catches debuggers that attached before
 * the daemon started or via methods the eBPF hook doesn't cover.
 */

#ifndef OWLBEAR_DEBUGGER_DETECT_H
#define OWLBEAR_DEBUGGER_DETECT_H

#include <sys/types.h>

/* Debugger detection state */
struct owl_debugger_detect {
	pid_t target_pid;
	pid_t last_tracer;    /* 0 = none last check */
};

/**
 * owl_debugger_detect_init - Initialize debugger detection context
 * @dd:     Detection context
 * @target: PID to monitor
 *
 * Returns 0 on success, -1 on null context.
 */
int owl_debugger_detect_init(struct owl_debugger_detect *dd, pid_t target);

/**
 * owl_check_tracer_pid - Read TracerPid from /proc/<pid>/status
 * @pid: Process to check
 *
 * Pure function. Opens /proc/<pid>/status, parses TracerPid field.
 * Returns the tracer PID (0 = no tracer), or -1 on error.
 */
int owl_check_tracer_pid(pid_t pid);

/**
 * owl_debugger_detect_check - Stateful debugger detection check
 * @dd: Detection context
 *
 * Calls owl_check_tracer_pid() on the target, detects 0->nonzero
 * transitions (debugger newly attached).
 *
 * Returns:
 *   0x01 — tracer newly detected (state transition)
 *   0x00 — no change (still no tracer, or tracer already known)
 *   -1   — error (null context or proc read failure)
 */
int owl_debugger_detect_check(struct owl_debugger_detect *dd);

#endif /* OWLBEAR_DEBUGGER_DETECT_H */
