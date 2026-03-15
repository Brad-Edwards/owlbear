/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * clock_validator.h - Multi-clock drift detection for speed hack detection
 *
 * Compares CLOCK_MONOTONIC vs CLOCK_MONOTONIC_RAW elapsed times to detect
 * userspace time manipulation (LD_PRELOAD hooks on clock_gettime, vDSO
 * patching). On ARM64, also reads CNTVCT_EL0 as a third reference.
 *
 * Speed hacks that accelerate CLOCK_MONOTONIC cause measurable drift
 * against CLOCK_MONOTONIC_RAW (kernel-internal, unhookable).
 */

#ifndef OWLBEAR_CLOCK_VALIDATOR_H
#define OWLBEAR_CLOCK_VALIDATOR_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

/* Clock drift detection state */
struct owl_clock_validator {
	pid_t    target_pid;
	bool     baseline_set;
	uint64_t baseline_mono_ns;
	uint64_t baseline_raw_ns;
#ifdef __aarch64__
	uint64_t baseline_cntvct;
	uint64_t cntfrq;
#endif
};

/* 50ms threshold — NTP slew is ~500us/s (2.5ms over 5s). 50ms is well above. */
#define OWL_CLOCK_DRIFT_THRESHOLD_NS (50ULL * 1000000ULL)

/**
 * owl_clock_compute_drift_ns - Compute absolute drift between two elapsed times
 * @mono_elapsed_ns: Elapsed time from CLOCK_MONOTONIC
 * @raw_elapsed_ns:  Elapsed time from CLOCK_MONOTONIC_RAW
 *
 * Pure function. Returns abs(mono - raw) in nanoseconds.
 */
int64_t owl_clock_compute_drift_ns(int64_t mono_elapsed_ns,
				   int64_t raw_elapsed_ns);

/**
 * owl_clock_validator_init - Initialize clock validation context
 * @cv:     Validation context
 * @target: PID to monitor (informational, checks daemon clocks)
 *
 * Returns 0 on success, -1 on null context.
 */
int owl_clock_validator_init(struct owl_clock_validator *cv, pid_t target);

/**
 * owl_clock_validator_check - Perform clock drift check
 * @cv: Validation context
 *
 * First call: captures baselines, returns 0.
 * Subsequent: computes drift, updates rolling baseline.
 *
 * Returns:
 *   0x00 — no drift detected
 *   0x01 — clock drift exceeds threshold
 *   -1   — error (null context or clock read failure)
 */
int owl_clock_validator_check(struct owl_clock_validator *cv);

#ifdef __aarch64__
/**
 * owl_clock_read_cntvct - Read ARM64 virtual counter (CNTVCT_EL0)
 *
 * Returns the raw counter value.
 */
uint64_t owl_clock_read_cntvct(void);

/**
 * owl_clock_read_cntfrq - Read ARM64 counter frequency (CNTFRQ_EL0)
 *
 * Returns the counter frequency in Hz.
 */
uint64_t owl_clock_read_cntfrq(void);
#endif

#endif /* OWLBEAR_CLOCK_VALIDATOR_H */
