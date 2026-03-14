/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * test_policy.c - Unit tests for the policy engine
 *
 * Written BEFORE the implementation. These define the expected behavior.
 */

#include "test_harness.h"
#include "owlbear_events.h"
#include "policy.h"

/* -------------------------------------------------------------------------
 * Initialization tests
 * ----------------------------------------------------------------------- */

TEST(policy_init_defaults_to_observe) {
	struct owl_policy p;
	owl_policy_init(&p);

	ASSERT_EQ(p.rule_count, 0);
	ASSERT_EQ(p.default_action, OWL_ACT_OBSERVE);
}

TEST(policy_evaluate_no_rules_returns_default) {
	struct owl_policy p;
	owl_policy_init(&p);

	enum owl_policy_action act = owl_policy_evaluate(
		&p, OWL_EVENT_PTRACE_ATTEMPT, OWL_SEV_CRITICAL);

	ASSERT_EQ(act, OWL_ACT_OBSERVE);
}

/* -------------------------------------------------------------------------
 * Rule matching tests
 * ----------------------------------------------------------------------- */

TEST(policy_exact_event_match) {
	struct owl_policy p;
	owl_policy_init(&p);

	int ret = owl_policy_add_rule(&p, OWL_EVENT_PTRACE_ATTEMPT,
				      OWL_SEV_INFO, OWL_ACT_BLOCK);
	ASSERT_EQ(ret, 0);

	/* Matching event type and sufficient severity -> BLOCK */
	enum owl_policy_action act = owl_policy_evaluate(
		&p, OWL_EVENT_PTRACE_ATTEMPT, OWL_SEV_CRITICAL);
	ASSERT_EQ(act, OWL_ACT_BLOCK);

	/* Non-matching event type -> default */
	act = owl_policy_evaluate(&p, OWL_EVENT_PROCESS_CREATE, OWL_SEV_CRITICAL);
	ASSERT_EQ(act, OWL_ACT_OBSERVE);
}

TEST(policy_severity_threshold) {
	struct owl_policy p;
	owl_policy_init(&p);

	/* Rule: block ptrace only if severity >= WARN */
	owl_policy_add_rule(&p, OWL_EVENT_PTRACE_ATTEMPT,
			    OWL_SEV_WARN, OWL_ACT_BLOCK);

	/* INFO < WARN -> no match, default */
	enum owl_policy_action act = owl_policy_evaluate(
		&p, OWL_EVENT_PTRACE_ATTEMPT, OWL_SEV_INFO);
	ASSERT_EQ(act, OWL_ACT_OBSERVE);

	/* WARN >= WARN -> match */
	act = owl_policy_evaluate(&p, OWL_EVENT_PTRACE_ATTEMPT, OWL_SEV_WARN);
	ASSERT_EQ(act, OWL_ACT_BLOCK);

	/* CRITICAL >= WARN -> match */
	act = owl_policy_evaluate(&p, OWL_EVENT_PTRACE_ATTEMPT, OWL_SEV_CRITICAL);
	ASSERT_EQ(act, OWL_ACT_BLOCK);
}

TEST(policy_wildcard_event_type) {
	struct owl_policy p;
	owl_policy_init(&p);

	/* Rule: kill on any CRITICAL event (event_type=0 is wildcard) */
	owl_policy_add_rule(&p, 0, OWL_SEV_CRITICAL, OWL_ACT_KILL);

	/* Any event with CRITICAL severity should match */
	ASSERT_EQ(owl_policy_evaluate(&p, OWL_EVENT_PTRACE_ATTEMPT,
				      OWL_SEV_CRITICAL), OWL_ACT_KILL);
	ASSERT_EQ(owl_policy_evaluate(&p, OWL_EVENT_VM_READV_ATTEMPT,
				      OWL_SEV_CRITICAL), OWL_ACT_KILL);
	ASSERT_EQ(owl_policy_evaluate(&p, OWL_EVENT_PAC_KEY_CHANGED,
				      OWL_SEV_CRITICAL), OWL_ACT_KILL);

	/* Non-critical should NOT match */
	ASSERT_EQ(owl_policy_evaluate(&p, OWL_EVENT_PTRACE_ATTEMPT,
				      OWL_SEV_WARN), OWL_ACT_OBSERVE);
}

TEST(policy_first_match_wins) {
	struct owl_policy p;
	owl_policy_init(&p);

	/* Rule 1: block ptrace at any severity */
	owl_policy_add_rule(&p, OWL_EVENT_PTRACE_ATTEMPT,
			    OWL_SEV_INFO, OWL_ACT_BLOCK);

	/* Rule 2: kill on any critical (wildcard) */
	owl_policy_add_rule(&p, 0, OWL_SEV_CRITICAL, OWL_ACT_KILL);

	/* Ptrace+CRITICAL should match rule 1 first -> BLOCK, not KILL */
	enum owl_policy_action act = owl_policy_evaluate(
		&p, OWL_EVENT_PTRACE_ATTEMPT, OWL_SEV_CRITICAL);
	ASSERT_EQ(act, OWL_ACT_BLOCK);

	/* Non-ptrace CRITICAL should match rule 2 -> KILL */
	act = owl_policy_evaluate(&p, OWL_EVENT_VM_READV_ATTEMPT,
				  OWL_SEV_CRITICAL);
	ASSERT_EQ(act, OWL_ACT_KILL);
}

/* -------------------------------------------------------------------------
 * Capacity tests
 * ----------------------------------------------------------------------- */

TEST(policy_max_rules) {
	struct owl_policy p;
	owl_policy_init(&p);

	/* Fill to capacity */
	for (int i = 0; i < OWL_POLICY_MAX_RULES; i++) {
		int ret = owl_policy_add_rule(&p, (uint32_t)(i + 1),
					      OWL_SEV_INFO, OWL_ACT_LOG);
		ASSERT_EQ(ret, 0);
	}

	ASSERT_EQ(p.rule_count, OWL_POLICY_MAX_RULES);

	/* One more should fail */
	int ret = owl_policy_add_rule(&p, 0xFFFF, OWL_SEV_INFO, OWL_ACT_LOG);
	ASSERT_EQ(ret, -1);
}

/* -------------------------------------------------------------------------
 * Action string tests
 * ----------------------------------------------------------------------- */

TEST(policy_action_strings) {
	ASSERT_STR_EQ(owl_policy_action_str(OWL_ACT_OBSERVE), "OBSERVE");
	ASSERT_STR_EQ(owl_policy_action_str(OWL_ACT_LOG), "LOG");
	ASSERT_STR_EQ(owl_policy_action_str(OWL_ACT_BLOCK), "BLOCK");
	ASSERT_STR_EQ(owl_policy_action_str(OWL_ACT_KILL), "KILL");
}

/* -------------------------------------------------------------------------
 * Default action override test
 * ----------------------------------------------------------------------- */

TEST(policy_custom_default) {
	struct owl_policy p;
	owl_policy_init(&p);
	p.default_action = OWL_ACT_LOG;

	/* No rules match -> custom default */
	enum owl_policy_action act = owl_policy_evaluate(
		&p, OWL_EVENT_PROCESS_CREATE, OWL_SEV_INFO);
	ASSERT_EQ(act, OWL_ACT_LOG);
}

/* -------------------------------------------------------------------------
 * Runner
 * ----------------------------------------------------------------------- */

int main(void)
{
	printf("=== Owlbear Policy Engine Tests ===\n");

	RUN_TEST(policy_init_defaults_to_observe);
	RUN_TEST(policy_evaluate_no_rules_returns_default);
	RUN_TEST(policy_exact_event_match);
	RUN_TEST(policy_severity_threshold);
	RUN_TEST(policy_wildcard_event_type);
	RUN_TEST(policy_first_match_wins);
	RUN_TEST(policy_max_rules);
	RUN_TEST(policy_action_strings);
	RUN_TEST(policy_custom_default);

	TEST_SUMMARY();
	return test_failures;
}
