// SPDX-License-Identifier: GPL-2.0-only
/*
 * policy.c - Event policy engine
 *
 * Simple rule-based policy: maps (event_type, severity) to an action.
 * Rules are evaluated in insertion order; first match wins.
 * Event type 0 is a wildcard (matches any event type).
 */

#include <string.h>

#include "policy.h"

void owl_policy_init(struct owl_policy *policy)
{
	memset(policy, 0, sizeof(*policy));
	policy->rule_count = 0;
	policy->default_action = OWL_ACT_OBSERVE;
}

int owl_policy_add_rule(struct owl_policy *policy, uint32_t event_type,
			uint32_t min_sev, enum owl_policy_action action)
{
	if (policy->rule_count >= OWL_POLICY_MAX_RULES)
		return -1;

	struct owl_policy_rule *rule = &policy->rules[policy->rule_count];
	rule->event_type = event_type;
	rule->min_severity = min_sev;
	rule->action = action;
	policy->rule_count++;

	return 0;
}

enum owl_policy_action owl_policy_evaluate(const struct owl_policy *policy,
					   uint32_t event_type,
					   uint32_t severity)
{
	for (int i = 0; i < policy->rule_count; i++) {
		const struct owl_policy_rule *rule = &policy->rules[i];

		/* Event type must match (0 = wildcard) */
		if (rule->event_type != 0 && rule->event_type != event_type)
			continue;

		/* Severity must meet threshold */
		if (severity < rule->min_severity)
			continue;

		return rule->action;
	}

	return policy->default_action;
}

const char *owl_policy_action_str(enum owl_policy_action action)
{
	switch (action) {
	case OWL_ACT_OBSERVE: return "OBSERVE";
	case OWL_ACT_LOG:     return "LOG";
	case OWL_ACT_BLOCK:   return "BLOCK";
	case OWL_ACT_KILL:    return "KILL";
	default:              return "UNKNOWN";
	}
}
