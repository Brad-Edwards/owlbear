/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * test_preload_detect.c - Tests for LD_PRELOAD environ detection
 *
 * Tests the pure environ scanning function and the I/O wrapper
 * that reads /proc/<pid>/environ.
 */

#include <string.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>

#include "test_harness.h"
#include "preload_detect.h"

static int backoffs;
int __wrap_usleep(useconds_t duration)
{
	(void)duration;
	backoffs++;
	return 0;
}

/* -------------------------------------------------------------------------
 * Pure function: owl_scan_environ_for_preload
 * ----------------------------------------------------------------------- */

TEST(scan_preload_found) {
	/* Synthetic environ buffer with LD_PRELOAD set */
	const char buf[] = "HOME=/h\0LD_PRELOAD=/path/hook.so\0PATH=/bin\0";
	char value[256] = {0};

	int ret = owl_scan_environ_for_preload(buf, sizeof(buf) - 1,
					       value, sizeof(value));
	ASSERT_EQ(ret, 1);
	ASSERT_STR_EQ(value, "/path/hook.so");
}

TEST(scan_preload_not_found) {
	const char buf[] = "HOME=/h\0PATH=/bin\0TERM=xterm\0";
	char value[256] = {0};

	int ret = owl_scan_environ_for_preload(buf, sizeof(buf) - 1,
					       value, sizeof(value));
	ASSERT_EQ(ret, 0);
}

TEST(scan_null_buffer_returns_error) {
	int ret = owl_scan_environ_for_preload(NULL, 0, NULL, 0);
	ASSERT_EQ(ret, -1);
}

TEST(scan_preload_null_output) {
	/* LD_PRELOAD present, but value_out is NULL — should return 1 without crash */
	const char buf[] = "LD_PRELOAD=/evil.so\0PATH=/bin\0";

	int ret = owl_scan_environ_for_preload(buf, sizeof(buf) - 1, NULL, 0);
	ASSERT_EQ(ret, 1);
}

/* -------------------------------------------------------------------------
 * I/O wrapper: owl_check_preload_env
 * ----------------------------------------------------------------------- */

TEST(check_preload_self) {
	/* Test process should not have LD_PRELOAD set */
	char value[256] = {0};
	int ret = owl_check_preload_env(getpid(), value, sizeof(value));
	ASSERT_EQ(ret, 0);
}

TEST(exited_process_does_not_back_off) {
	pid_t child = fork();
	ASSERT_TRUE(child >= 0);
	if (child == 0) _exit(0);
	ASSERT_EQ(waitpid(child, NULL, 0), child);
	backoffs = 0;
	ASSERT_EQ(owl_check_preload_env(child, NULL, 0), -1);
	ASSERT_EQ(backoffs, 0);
}

/* -------------------------------------------------------------------------
 * Runner
 * ----------------------------------------------------------------------- */

int main(void)
{
	printf("=== Owlbear Preload Detection Tests ===\n");

	RUN_TEST(scan_preload_found);
	RUN_TEST(scan_preload_not_found);
	RUN_TEST(scan_null_buffer_returns_error);
	RUN_TEST(scan_preload_null_output);
	RUN_TEST(check_preload_self);
	RUN_TEST(exited_process_does_not_back_off);

	TEST_SUMMARY();
	return test_failures;
}
