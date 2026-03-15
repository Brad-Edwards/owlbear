/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * test_clock_validator.c - Tests for multi-clock drift detection
 *
 * Tests the pure drift computation function and the stateful
 * clock validator context initialization and null handling.
 */

#include <string.h>
#include <sys/types.h>

#include "test_harness.h"
#include "clock_validator.h"

/* -------------------------------------------------------------------------
 * Pure function: owl_clock_compute_drift_ns
 * ----------------------------------------------------------------------- */

TEST(compute_drift_ns_zero) {
	/* Identical elapsed times produce zero drift */
	int64_t drift = owl_clock_compute_drift_ns(1000000000LL, 1000000000LL);
	ASSERT_EQ(drift, 0);
}

TEST(compute_drift_ns_positive) {
	/* MONO faster than RAW = positive drift (speed hack) */
	int64_t drift = owl_clock_compute_drift_ns(2000000000LL, 1000000000LL);
	ASSERT_EQ(drift, 1000000000LL);
}

TEST(compute_drift_ns_negative) {
	/* MONO slower than RAW = still absolute drift */
	int64_t drift = owl_clock_compute_drift_ns(500000000LL, 1000000000LL);
	ASSERT_EQ(drift, 500000000LL);
}

TEST(compute_drift_ns_within_threshold) {
	/* 40ms drift is below 50ms threshold */
	int64_t mono = 5000000000LL + 40000000LL;  /* 5s + 40ms */
	int64_t raw  = 5000000000LL;                /* 5s exactly */
	int64_t drift = owl_clock_compute_drift_ns(mono, raw);
	ASSERT_EQ(drift, 40000000LL);
	ASSERT_TRUE(drift < (int64_t)OWL_CLOCK_DRIFT_THRESHOLD_NS);
}

/* -------------------------------------------------------------------------
 * Stateful context: owl_clock_validator_init / _check
 * ----------------------------------------------------------------------- */

TEST(init_sets_state) {
	struct owl_clock_validator cv;
	memset(&cv, 0xFF, sizeof(cv));

	int ret = owl_clock_validator_init(&cv, 42);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(cv.target_pid, 42);
	ASSERT_EQ(cv.baseline_set, false);
}

TEST(init_null_returns_error) {
	int ret = owl_clock_validator_init(NULL, 42);
	ASSERT_EQ(ret, -1);
}

TEST(check_null_returns_error) {
	int ret = owl_clock_validator_check(NULL);
	ASSERT_EQ(ret, -1);
}

/* -------------------------------------------------------------------------
 * Runner
 * ----------------------------------------------------------------------- */

int main(void)
{
	printf("=== Owlbear Clock Validator Tests ===\n");

	RUN_TEST(compute_drift_ns_zero);
	RUN_TEST(compute_drift_ns_positive);
	RUN_TEST(compute_drift_ns_negative);
	RUN_TEST(compute_drift_ns_within_threshold);
	RUN_TEST(init_sets_state);
	RUN_TEST(init_null_returns_error);
	RUN_TEST(check_null_returns_error);

	TEST_SUMMARY();
	return test_failures;
}
