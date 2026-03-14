// SPDX-License-Identifier: GPL-2.0-only
/*
 * scanner.c - Byte-pattern signature scanning engine
 *
 * Linear scan with wildcard support. Not optimized (no Aho-Corasick) —
 * sufficient for a prototype scanning a single game process.
 */

#include <ctype.h>
#include <string.h>

#include "scanner.h"

/* -------------------------------------------------------------------------
 * Hex parsing helpers
 * ----------------------------------------------------------------------- */

static int hex_digit(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

/* -------------------------------------------------------------------------
 * Pattern parsing
 * ----------------------------------------------------------------------- */

int owl_sig_parse_pattern(struct owl_sig_rule *rule, const char *name,
			  const char *pattern)
{
	int len = 0;
	const char *p = pattern;

	memset(rule, 0, sizeof(*rule));
	strncpy(rule->name, name, OWL_SIG_MAX_NAME - 1);

	while (*p != '\0' && len < OWL_SIG_MAX_PATTERN) {
		/* Skip whitespace */
		while (*p == ' ' || *p == '\t')
			p++;

		if (*p == '\0')
			break;

		/* Check for wildcard */
		if (p[0] == '?' && p[1] == '?') {
			rule->pattern[len].wildcard = true;
			rule->pattern[len].value = 0;
			len++;
			p += 2;
			continue;
		}

		/* Parse hex byte */
		int hi = hex_digit(p[0]);
		if (hi < 0)
			return -1;

		if (p[1] == '\0')
			return -1; /* Incomplete byte */

		int lo = hex_digit(p[1]);
		if (lo < 0)
			return -1;

		rule->pattern[len].value = (uint8_t)((hi << 4) | lo);
		rule->pattern[len].wildcard = false;
		len++;
		p += 2;
	}

	if (len == 0)
		return -1;

	rule->pattern_len = len;
	return 0;
}

/* -------------------------------------------------------------------------
 * Database operations
 * ----------------------------------------------------------------------- */

void owl_sig_db_init(struct owl_sig_db *db)
{
	memset(db, 0, sizeof(*db));
}

int owl_sig_db_add(struct owl_sig_db *db, const struct owl_sig_rule *rule)
{
	if (db->rule_count >= OWL_SIG_MAX_RULES)
		return -1;

	memcpy(&db->rules[db->rule_count], rule, sizeof(*rule));
	db->rule_count++;
	return 0;
}

/* -------------------------------------------------------------------------
 * Pattern matching
 * ----------------------------------------------------------------------- */

bool owl_sig_match_single(const struct owl_sig_rule *rule,
			  const uint8_t *buf, size_t buf_len,
			  size_t *offset)
{
	if (rule->pattern_len <= 0)
		return false;

	if ((size_t)rule->pattern_len > buf_len)
		return false;

	size_t end = buf_len - (size_t)rule->pattern_len;

	for (size_t i = 0; i <= end; i++) {
		bool match = true;

		for (int j = 0; j < rule->pattern_len; j++) {
			if (rule->pattern[j].wildcard)
				continue;

			if (buf[i + (size_t)j] != rule->pattern[j].value) {
				match = false;
				break;
			}
		}

		if (match) {
			if (offset)
				*offset = i;
			return true;
		}
	}

	return false;
}

int owl_sig_scan(const struct owl_sig_db *db, const uint8_t *buf,
		 size_t buf_len, struct owl_sig_match *matches,
		 int max_matches)
{
	int found = 0;

	for (int r = 0; r < db->rule_count && found < max_matches; r++) {
		const struct owl_sig_rule *rule = &db->rules[r];
		size_t offset;

		if (owl_sig_match_single(rule, buf, buf_len, &offset)) {
			matches[found].rule_name = rule->name;
			matches[found].offset = offset;
			found++;
		}
	}

	return found;
}
