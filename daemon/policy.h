/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * policy.h - Event policy engine interface
 *
 * Maps event types to actions (observe, log, block, kill).
 * Default policy: observe all. Can be overridden per event type.
 */

#ifndef OWLBEAR_POLICY_H
#define OWLBEAR_POLICY_H

#include <stdbool.h>
#include <stdint.h>

/* Actions the policy engine can prescribe */
enum owl_policy_action {
	OWL_ACT_OBSERVE = 0,   /* Log only, no intervention */
	OWL_ACT_LOG     = 1,   /* Log with elevated priority */
	OWL_ACT_BLOCK   = 2,   /* Deny the operation (where enforceable) */
	OWL_ACT_KILL    = 3,   /* Terminate the game process */
};

/* Maximum number of policy rules */
#define OWL_POLICY_MAX_RULES 64

/* A single policy rule: event type -> action */
struct owl_policy_rule {
	uint32_t event_type;          /* 0 = wildcard (matches all) */
	uint32_t min_severity;        /* Minimum severity to trigger */
	enum owl_policy_action action;
};

/* Policy engine state */
struct owl_policy {
	struct owl_policy_rule rules[OWL_POLICY_MAX_RULES];
	int rule_count;
	enum owl_policy_action default_action;
};

/**
 * owl_policy_init - Initialize policy with default (observe all)
 * @policy: Policy to initialize
 */
void owl_policy_init(struct owl_policy *policy);

/**
 * owl_policy_add_rule - Add a rule to the policy
 * @policy:     Policy to modify
 * @event_type: Event type to match (0 = wildcard)
 * @min_sev:    Minimum severity to trigger this rule
 * @action:     Action to take
 *
 * Returns 0 on success, -1 if rule table is full.
 */
int owl_policy_add_rule(struct owl_policy *policy, uint32_t event_type,
			uint32_t min_sev, enum owl_policy_action action);

/**
 * owl_policy_evaluate - Determine action for an event
 * @policy:     Policy to evaluate against
 * @event_type: Event type
 * @severity:   Event severity
 *
 * Returns the action to take. Rules are evaluated in order;
 * first match wins. If no rule matches, default_action is returned.
 */
enum owl_policy_action owl_policy_evaluate(const struct owl_policy *policy,
					   uint32_t event_type,
					   uint32_t severity);

/**
 * owl_policy_action_str - Get string representation of an action
 */
const char *owl_policy_action_str(enum owl_policy_action action);

#endif /* OWLBEAR_POLICY_H */
