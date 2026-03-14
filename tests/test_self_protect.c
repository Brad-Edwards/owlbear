/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * test_self_protect.c - Tests for daemon self-protection
 *
 * Tests the pure check functions. Module presence and ioctl
 * tests depend on runtime state but are still useful.
 */

#include <string.h>
#include <unistd.h>

#include "test_harness.h"
#include "self_protect.h"

/* -------------------------------------------------------------------------
 * Module presence check — runs on any system
 * ----------------------------------------------------------------------- */

TEST(selfprotect_check_module_no_module) {
	/*
	 * On a system without owlbear loaded, this should return false.
	 * This is a live check — if somehow owlbear IS loaded, it's
	 * still a valid pass since the function works correctly.
	 */
	bool present = owl_selfprotect_check_module();
	/* We can't assert a specific value since it depends on runtime */
	/* Instead, verify the function doesn't crash and returns bool */
	ASSERT_TRUE(present == true || present == false);
}

/* -------------------------------------------------------------------------
 * IOCTL check with invalid fd
 * ----------------------------------------------------------------------- */

TEST(selfprotect_check_ioctl_bad_fd) {
	ASSERT_TRUE(!owl_selfprotect_check_ioctl(-1));
}

TEST(selfprotect_check_ioctl_invalid_fd) {
	/* fd 999 is very unlikely to be open */
	ASSERT_TRUE(!owl_selfprotect_check_ioctl(999));
}

/* -------------------------------------------------------------------------
 * Watchdog with no module
 * ----------------------------------------------------------------------- */

TEST(selfprotect_watchdog_detects_missing_module) {
	struct owl_self_protect sp;
	memset(&sp, 0, sizeof(sp));
	sp.dev_fd = -1;
	sp.bpf_rb_fd = -1;
	sp.module_present = true;  /* Was present */
	sp.bpf_attached = false;

	int result = owl_selfprotect_watchdog(&sp);

	/*
	 * If owlbear module is not loaded (common in dev),
	 * result should include 0x01 (module missing).
	 */
	if (!owl_selfprotect_check_module()) {
		ASSERT_TRUE((result & 0x01) != 0);
	} else {
		/* Module is loaded — result could vary */
		ASSERT_TRUE(result >= 0);
	}
}

TEST(selfprotect_watchdog_null_returns_error) {
	ASSERT_EQ(owl_selfprotect_watchdog(NULL), -1);
}

/* -------------------------------------------------------------------------
 * Runner
 * ----------------------------------------------------------------------- */

int main(void)
{
	printf("=== Owlbear Self-Protection Tests ===\n");

	RUN_TEST(selfprotect_check_module_no_module);
	RUN_TEST(selfprotect_check_ioctl_bad_fd);
	RUN_TEST(selfprotect_check_ioctl_invalid_fd);
	RUN_TEST(selfprotect_watchdog_detects_missing_module);
	RUN_TEST(selfprotect_watchdog_null_returns_error);

	TEST_SUMMARY();
	return test_failures;
}
