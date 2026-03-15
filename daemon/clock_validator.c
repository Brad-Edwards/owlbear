// SPDX-License-Identifier: GPL-2.0-only
/*
 * clock_validator.c - Multi-clock drift detection for speed hack detection
 *
 * Compares CLOCK_MONOTONIC vs CLOCK_MONOTONIC_RAW to detect userspace
 * time manipulation. CLOCK_MONOTONIC can be hooked via LD_PRELOAD or
 * vDSO patching; CLOCK_MONOTONIC_RAW is kernel-internal and unhookable.
 *
 * On ARM64, also reads CNTVCT_EL0 as a third independent time source.
 */

#include <string.h>
#include <time.h>

#include "clock_validator.h"

/* -------------------------------------------------------------------------
 * Pure drift computation
 * ----------------------------------------------------------------------- */

int64_t owl_clock_compute_drift_ns(int64_t mono_elapsed_ns,
				   int64_t raw_elapsed_ns)
{
	int64_t diff = mono_elapsed_ns - raw_elapsed_ns;
	return diff < 0 ? -diff : diff;
}

/* -------------------------------------------------------------------------
 * ARM64 counter access
 * ----------------------------------------------------------------------- */

#ifdef __aarch64__
uint64_t owl_clock_read_cntvct(void)
{
	uint64_t val;
	__asm__ volatile("mrs %0, cntvct_el0" : "=r"(val));
	return val;
}

uint64_t owl_clock_read_cntfrq(void)
{
	uint64_t val;
	__asm__ volatile("mrs %0, cntfrq_el0" : "=r"(val));
	return val;
}
#endif

/* -------------------------------------------------------------------------
 * Helper: read clock into nanoseconds
 * ----------------------------------------------------------------------- */

static int read_clock_ns(clockid_t clk, uint64_t *out_ns)
{
	struct timespec ts;

	if (clock_gettime(clk, &ts) < 0)
		return -1;

	*out_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
	return 0;
}

/* -------------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------- */

int owl_clock_validator_init(struct owl_clock_validator *cv, pid_t target)
{
	if (!cv)
		return -1;

	memset(cv, 0, sizeof(*cv));
	cv->target_pid = target;
	cv->baseline_set = false;

	return 0;
}

int owl_clock_validator_check(struct owl_clock_validator *cv)
{
	if (!cv)
		return -1;

	uint64_t mono_ns, raw_ns;

	if (read_clock_ns(CLOCK_MONOTONIC, &mono_ns) < 0)
		return -1;
	if (read_clock_ns(CLOCK_MONOTONIC_RAW, &raw_ns) < 0)
		return -1;

#ifdef __aarch64__
	uint64_t cntvct = owl_clock_read_cntvct();
#endif

	/* First call: capture baselines */
	if (!cv->baseline_set) {
		cv->baseline_mono_ns = mono_ns;
		cv->baseline_raw_ns = raw_ns;
#ifdef __aarch64__
		cv->baseline_cntvct = cntvct;
		cv->cntfrq = owl_clock_read_cntfrq();
#endif
		cv->baseline_set = true;
		return 0;
	}

	/* Compute elapsed times */
	int64_t mono_elapsed = (int64_t)(mono_ns - cv->baseline_mono_ns);
	int64_t raw_elapsed = (int64_t)(raw_ns - cv->baseline_raw_ns);

	int result = 0;

	/* Check MONOTONIC vs MONOTONIC_RAW drift */
	int64_t drift = owl_clock_compute_drift_ns(mono_elapsed, raw_elapsed);
	if ((uint64_t)drift > OWL_CLOCK_DRIFT_THRESHOLD_NS)
		result |= 0x01;

#ifdef __aarch64__
	/* Check CNTVCT_EL0 vs MONOTONIC_RAW */
	if (cv->cntfrq > 0) {
		uint64_t cntvct_elapsed = cntvct - cv->baseline_cntvct;
		/* Convert counter ticks to nanoseconds */
		int64_t cntvct_ns = (int64_t)((cntvct_elapsed * 1000000000ULL)
					      / cv->cntfrq);
		int64_t hw_drift = owl_clock_compute_drift_ns(cntvct_ns,
							      raw_elapsed);
		if ((uint64_t)hw_drift > OWL_CLOCK_DRIFT_THRESHOLD_NS)
			result |= 0x01;
	}
#endif

	/* Update rolling baselines */
	cv->baseline_mono_ns = mono_ns;
	cv->baseline_raw_ns = raw_ns;
#ifdef __aarch64__
	cv->baseline_cntvct = cntvct;
#endif

	return result;
}
