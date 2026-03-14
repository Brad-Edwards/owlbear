/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * test_heartbeat.c - Unit tests for heartbeat tracker (TDD)
 */

#include <string.h>

#include "test_harness.h"
#include "owlbear_events.h"
#include "heartbeat.h"

/* -------------------------------------------------------------------------
 * Init and registration
 * ----------------------------------------------------------------------- */

TEST(hb_init_inactive) {
	struct owl_hb_tracker hb;
	owl_hb_init(&hb);

	ASSERT_EQ(hb.active, false);
	ASSERT_EQ(hb.game_pid, 0);
	ASSERT_EQ(hb.missed_count, 0);
	ASSERT_EQ(hb.total_received, 0);
}

TEST(hb_register_activates) {
	struct owl_hb_tracker hb;
	owl_hb_init(&hb);
	owl_hb_register(&hb, 1234);

	ASSERT_EQ(hb.active, true);
	ASSERT_EQ(hb.game_pid, 1234);
}

/* -------------------------------------------------------------------------
 * Normal heartbeat processing
 * ----------------------------------------------------------------------- */

TEST(hb_process_normal) {
	struct owl_hb_tracker hb;
	owl_hb_init(&hb);
	owl_hb_register(&hb, 100);

	struct owl_heartbeat_game msg = {
		.timestamp_ns = 1000000000ULL,
		.pid = 100,
		.frame_count = 10,
		.state_hash = 0xABCD,
	};

	int ret = owl_hb_process(&hb, &msg);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(hb.total_received, 1);
	ASSERT_EQ(hb.last_frame_count, 10);
	ASSERT_EQ(hb.last_state_hash, 0xABCD);
}

TEST(hb_process_increments_count) {
	struct owl_hb_tracker hb;
	owl_hb_init(&hb);
	owl_hb_register(&hb, 100);

	struct owl_heartbeat_game msg = {
		.pid = 100, .frame_count = 1, .state_hash = 1,
	};

	owl_hb_process(&hb, &msg);
	msg.frame_count = 2;
	owl_hb_process(&hb, &msg);
	msg.frame_count = 3;
	owl_hb_process(&hb, &msg);

	ASSERT_EQ(hb.total_received, 3);
}

TEST(hb_process_resets_missed) {
	struct owl_hb_tracker hb;
	owl_hb_init(&hb);
	owl_hb_register(&hb, 100);
	hb.missed_count = 5;  /* Simulate prior misses */

	struct owl_heartbeat_game msg = {
		.pid = 100, .frame_count = 10, .state_hash = 1,
	};

	owl_hb_process(&hb, &msg);
	ASSERT_EQ(hb.missed_count, 0);
}

/* -------------------------------------------------------------------------
 * Anomaly detection
 * ----------------------------------------------------------------------- */

TEST(hb_detect_frame_rewind) {
	struct owl_hb_tracker hb;
	owl_hb_init(&hb);
	owl_hb_register(&hb, 100);

	struct owl_heartbeat_game msg = {
		.pid = 100, .frame_count = 100, .state_hash = 1,
	};

	owl_hb_process(&hb, &msg);

	/* Frame count goes backwards — suspicious */
	msg.frame_count = 50;
	int ret = owl_hb_process(&hb, &msg);
	ASSERT_EQ(ret, 1);
}

TEST(hb_detect_frame_freeze) {
	struct owl_hb_tracker hb;
	owl_hb_init(&hb);
	owl_hb_register(&hb, 100);

	struct owl_heartbeat_game msg = {
		.pid = 100, .frame_count = 100, .state_hash = 1,
	};

	owl_hb_process(&hb, &msg);

	/* Same frame count twice — game may be frozen */
	int ret = owl_hb_process(&hb, &msg);
	ASSERT_EQ(ret, 1);
}

/* -------------------------------------------------------------------------
 * Timeout detection
 * ----------------------------------------------------------------------- */

TEST(hb_timeout_not_active) {
	struct owl_hb_tracker hb;
	owl_hb_init(&hb);

	struct timespec now = { .tv_sec = 100 };
	ASSERT_TRUE(!owl_hb_check_timeout(&hb, &now));
}

TEST(hb_timeout_fresh) {
	struct owl_hb_tracker hb;
	owl_hb_init(&hb);
	owl_hb_register(&hb, 100);

	/* Process a heartbeat to set last_received */
	struct owl_heartbeat_game msg = {
		.pid = 100, .frame_count = 1, .state_hash = 1,
	};
	owl_hb_process(&hb, &msg);

	/* Check 1 second later — should not be timed out */
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	now.tv_sec += 1;

	ASSERT_TRUE(!owl_hb_check_timeout(&hb, &now));
}

TEST(hb_timeout_expired) {
	struct owl_hb_tracker hb;
	owl_hb_init(&hb);
	owl_hb_register(&hb, 100);

	struct owl_heartbeat_game msg = {
		.pid = 100, .frame_count = 1, .state_hash = 1,
	};
	owl_hb_process(&hb, &msg);

	/* Check 10 seconds later — should be timed out */
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	now.tv_sec += OWL_HB_TIMEOUT_S + 1;

	ASSERT_TRUE(owl_hb_check_timeout(&hb, &now));
	ASSERT_EQ(hb.missed_count, 1);
}

/* -------------------------------------------------------------------------
 * Runner
 * ----------------------------------------------------------------------- */

int main(void)
{
	printf("=== Owlbear Heartbeat Tracker Tests ===\n");

	RUN_TEST(hb_init_inactive);
	RUN_TEST(hb_register_activates);
	RUN_TEST(hb_process_normal);
	RUN_TEST(hb_process_increments_count);
	RUN_TEST(hb_process_resets_missed);
	RUN_TEST(hb_detect_frame_rewind);
	RUN_TEST(hb_detect_frame_freeze);
	RUN_TEST(hb_timeout_not_active);
	RUN_TEST(hb_timeout_fresh);
	RUN_TEST(hb_timeout_expired);

	TEST_SUMMARY();
	return test_failures;
}
