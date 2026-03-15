/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * test_debugger_detect.c - Tests for TracerPid debugger detection
 *
 * Tests the pure TracerPid parsing function and the stateful
 * debugger detection context. All tests run without a debugger
 * attached to the test process.
 */

#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "test_harness.h"
#include "debugger_detect.h"

/* -------------------------------------------------------------------------
 * Pure function: owl_check_tracer_pid
 * ----------------------------------------------------------------------- */

TEST(check_tracer_pid_self) {
	/* No debugger attached to the test process */
	int tracer = owl_check_tracer_pid(getpid());
	ASSERT_EQ(tracer, 0);
}

TEST(check_tracer_pid_zero) {
	/* PID 0 is invalid — should return error */
	int tracer = owl_check_tracer_pid(0);
	ASSERT_EQ(tracer, -1);
}

TEST(check_tracer_pid_nonexistent) {
	/* No such process — should return error */
	int tracer = owl_check_tracer_pid(999999999);
	ASSERT_EQ(tracer, -1);
}

/* -------------------------------------------------------------------------
 * Stateful context: owl_debugger_detect_init / _check
 * ----------------------------------------------------------------------- */

TEST(detect_init_sets_target) {
	struct owl_debugger_detect dd;
	int ret = owl_debugger_detect_init(&dd, 12345);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(dd.target_pid, 12345);
	ASSERT_EQ(dd.last_tracer, 0);
}

TEST(detect_check_null_returns_error) {
	ASSERT_EQ(owl_debugger_detect_check(NULL), -1);
}

TEST(detect_check_no_debugger) {
	struct owl_debugger_detect dd;
	owl_debugger_detect_init(&dd, getpid());
	int result = owl_debugger_detect_check(&dd);
	ASSERT_EQ(result, 0);
}

/* -------------------------------------------------------------------------
 * Runner
 * ----------------------------------------------------------------------- */

int main(void)
{
	printf("=== Owlbear Debugger Detection Tests ===\n");

	RUN_TEST(check_tracer_pid_self);
	RUN_TEST(check_tracer_pid_zero);
	RUN_TEST(check_tracer_pid_nonexistent);
	RUN_TEST(detect_init_sets_target);
	RUN_TEST(detect_check_null_returns_error);
	RUN_TEST(detect_check_no_debugger);

	TEST_SUMMARY();
	return test_failures;
}
