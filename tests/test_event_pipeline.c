/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * test_event_pipeline.c - Tests for the event processing pipeline
 */

#include <string.h>

#include "test_harness.h"
#include "owlbear_events.h"
#include "policy.h"
#include "scanner.h"
#include "event_pipeline.h"

/* -------------------------------------------------------------------------
 * Helper: create a test event
 * ----------------------------------------------------------------------- */

static struct owlbear_event make_event(uint32_t type, uint32_t sev,
				       uint32_t pid, uint32_t target)
{
	struct owlbear_event ev;
	memset(&ev, 0, sizeof(ev));
	ev.event_type = type;
	ev.severity = sev;
	ev.pid = pid;
	ev.target_pid = target;
	return ev;
}

/* -------------------------------------------------------------------------
 * Policy integration tests
 * ----------------------------------------------------------------------- */

TEST(pipeline_observe_mode_downgrades_block) {
	struct owl_policy policy;
	struct owl_sig_db db;
	struct owl_pipeline pipe;

	owl_policy_init(&policy);
	owl_sig_db_init(&db);

	/* Rule: BLOCK on ptrace */
	owl_policy_add_rule(&policy, OWL_EVENT_PTRACE_ATTEMPT,
			    OWL_SEV_INFO, OWL_ACT_BLOCK);

	/* Observe mode (enforce=false) */
	owl_pipeline_init(&pipe, &policy, &db, NULL, NULL, 100, false, NULL);

	struct owlbear_event ev = make_event(OWL_EVENT_PTRACE_ATTEMPT,
					     OWL_SEV_CRITICAL, 50, 100);

	/* Should downgrade BLOCK to LOG in observe mode */
	enum owl_policy_action act = owl_pipeline_process(&pipe, &ev);
	ASSERT_EQ(act, OWL_ACT_LOG);
}

TEST(pipeline_enforce_mode_keeps_block) {
	struct owl_policy policy;
	struct owl_sig_db db;
	struct owl_pipeline pipe;

	owl_policy_init(&policy);
	owl_sig_db_init(&db);
	owl_policy_add_rule(&policy, OWL_EVENT_PTRACE_ATTEMPT,
			    OWL_SEV_INFO, OWL_ACT_BLOCK);

	/* Enforce mode */
	owl_pipeline_init(&pipe, &policy, &db, NULL, NULL, 100, true, NULL);

	struct owlbear_event ev = make_event(OWL_EVENT_PTRACE_ATTEMPT,
					     OWL_SEV_CRITICAL, 50, 100);

	enum owl_policy_action act = owl_pipeline_process(&pipe, &ev);
	ASSERT_EQ(act, OWL_ACT_BLOCK);
	ASSERT_EQ(pipe.actions_block, 1);
}

TEST(pipeline_observe_returns_observe_for_unmatched) {
	struct owl_policy policy;
	struct owl_sig_db db;
	struct owl_pipeline pipe;

	owl_policy_init(&policy);
	owl_sig_db_init(&db);

	owl_pipeline_init(&pipe, &policy, &db, NULL, NULL, 100, false, NULL);

	struct owlbear_event ev = make_event(OWL_EVENT_PROCESS_CREATE,
					     OWL_SEV_INFO, 50, 100);

	enum owl_policy_action act = owl_pipeline_process(&pipe, &ev);
	ASSERT_EQ(act, OWL_ACT_OBSERVE);
}

TEST(pipeline_counts_events) {
	struct owl_policy policy;
	struct owl_sig_db db;
	struct owl_pipeline pipe;

	owl_policy_init(&policy);
	owl_sig_db_init(&db);
	owl_pipeline_init(&pipe, &policy, &db, NULL, NULL, 100, false, NULL);

	struct owlbear_event ev = make_event(OWL_EVENT_PROCESS_CREATE,
					     OWL_SEV_INFO, 50, 100);

	owl_pipeline_process(&pipe, &ev);
	owl_pipeline_process(&pipe, &ev);
	owl_pipeline_process(&pipe, &ev);

	ASSERT_EQ(pipe.events_processed, 3);
}

TEST(pipeline_null_event_returns_observe) {
	struct owl_policy policy;
	struct owl_sig_db db;
	struct owl_pipeline pipe;

	owl_policy_init(&policy);
	owl_sig_db_init(&db);
	owl_pipeline_init(&pipe, &policy, &db, NULL, NULL, 100, false, NULL);

	ASSERT_EQ(owl_pipeline_process(&pipe, NULL), OWL_ACT_OBSERVE);
}

/* -------------------------------------------------------------------------
 * Signature scan tests (buffer variant)
 * ----------------------------------------------------------------------- */

TEST(pipeline_scan_buffer_finds_match) {
	struct owl_policy policy;
	struct owl_sig_db db;
	struct owl_pipeline pipe;
	struct owl_sig_rule rule;

	owl_policy_init(&policy);
	owl_sig_db_init(&db);

	/* Add a rule that matches "ABCD" */
	owl_sig_parse_pattern(&rule, "test_pattern", "41 42 43 44");
	owl_sig_db_add(&db, &rule);

	/* Add a rule for sig match events -> LOG */
	owl_policy_add_rule(&policy, OWL_EVENT_SIGNATURE_MATCH,
			    OWL_SEV_INFO, OWL_ACT_LOG);

	owl_pipeline_init(&pipe, &policy, &db, NULL, NULL, 100, false, NULL);

	uint8_t buf[] = {0x00, 0x41, 0x42, 0x43, 0x44, 0x00};
	int found = owl_pipeline_scan_buffer(&pipe, buf, sizeof(buf), 0x1000);

	ASSERT_EQ(found, 1);
	ASSERT_EQ(pipe.sig_matches, 1);
}

TEST(pipeline_scan_buffer_no_match) {
	struct owl_policy policy;
	struct owl_sig_db db;
	struct owl_pipeline pipe;
	struct owl_sig_rule rule;

	owl_policy_init(&policy);
	owl_sig_db_init(&db);
	owl_sig_parse_pattern(&rule, "test", "FF FF FF FF");
	owl_sig_db_add(&db, &rule);

	owl_pipeline_init(&pipe, &policy, &db, NULL, NULL, 100, false, NULL);

	uint8_t buf[] = {0x00, 0x01, 0x02, 0x03};
	int found = owl_pipeline_scan_buffer(&pipe, buf, sizeof(buf), 0x1000);

	ASSERT_EQ(found, 0);
	ASSERT_EQ(pipe.sig_matches, 0);
}

TEST(pipeline_scan_empty_db_returns_zero) {
	struct owl_policy policy;
	struct owl_sig_db db;
	struct owl_pipeline pipe;

	owl_policy_init(&policy);
	owl_sig_db_init(&db);
	owl_pipeline_init(&pipe, &policy, &db, NULL, NULL, 100, false, NULL);

	uint8_t buf[] = {0x41, 0x42};
	int found = owl_pipeline_scan_buffer(&pipe, buf, sizeof(buf), 0);

	ASSERT_EQ(found, 0);
}

/* -------------------------------------------------------------------------
 * Runner
 * ----------------------------------------------------------------------- */

int main(void)
{
	printf("=== Owlbear Event Pipeline Tests ===\n");

	RUN_TEST(pipeline_observe_mode_downgrades_block);
	RUN_TEST(pipeline_enforce_mode_keeps_block);
	RUN_TEST(pipeline_observe_returns_observe_for_unmatched);
	RUN_TEST(pipeline_counts_events);
	RUN_TEST(pipeline_null_event_returns_observe);
	RUN_TEST(pipeline_scan_buffer_finds_match);
	RUN_TEST(pipeline_scan_buffer_no_match);
	RUN_TEST(pipeline_scan_empty_db_returns_zero);

	TEST_SUMMARY();
	return test_failures;
}
