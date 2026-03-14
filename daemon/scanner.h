/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * scanner.h - Byte-pattern signature scanning engine
 *
 * Scans memory buffers for known cheat signatures. Patterns are
 * hex byte sequences with '?' wildcards (match any byte).
 *
 * Pattern format: "4D 5A 90 00 ?? ?? ?? ?? 50 45"
 *   - Two hex chars per byte, space-separated
 *   - "??" matches any byte value
 */

#ifndef OWLBEAR_SCANNER_H
#define OWLBEAR_SCANNER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Maximum pattern length in bytes */
#define OWL_SIG_MAX_PATTERN  128

/* Maximum number of signatures */
#define OWL_SIG_MAX_RULES    256

/* Maximum rule name length */
#define OWL_SIG_MAX_NAME     48

/* A single byte in a pattern: value + wildcard flag */
struct owl_sig_byte {
	uint8_t value;
	bool    wildcard;    /* true = match any byte */
};

/* A compiled signature rule */
struct owl_sig_rule {
	char               name[OWL_SIG_MAX_NAME];
	struct owl_sig_byte pattern[OWL_SIG_MAX_PATTERN];
	int                pattern_len;
};

/* Signature database */
struct owl_sig_db {
	struct owl_sig_rule rules[OWL_SIG_MAX_RULES];
	int                 rule_count;
};

/* Match result */
struct owl_sig_match {
	const char *rule_name;
	size_t      offset;      /* Byte offset within the scanned buffer */
};

/**
 * owl_sig_db_init - Initialize an empty signature database
 */
void owl_sig_db_init(struct owl_sig_db *db);

/**
 * owl_sig_parse_pattern - Parse a hex pattern string into a compiled rule
 * @rule:    Output rule
 * @name:    Rule name
 * @pattern: Pattern string (e.g., "4D 5A ?? ?? 50 45")
 *
 * Returns 0 on success, -1 on parse error.
 */
int owl_sig_parse_pattern(struct owl_sig_rule *rule, const char *name,
			  const char *pattern);

/**
 * owl_sig_db_add - Add a compiled rule to the database
 * @db:   Database
 * @rule: Rule to add (copied into database)
 *
 * Returns 0 on success, -1 if database is full.
 */
int owl_sig_db_add(struct owl_sig_db *db, const struct owl_sig_rule *rule);

/**
 * owl_sig_scan - Scan a buffer against all signatures in the database
 * @db:         Signature database
 * @buf:        Buffer to scan
 * @buf_len:    Buffer length
 * @matches:    Output array for matches
 * @max_matches: Maximum matches to return
 *
 * Returns number of matches found (0 = clean).
 */
int owl_sig_scan(const struct owl_sig_db *db, const uint8_t *buf,
		 size_t buf_len, struct owl_sig_match *matches,
		 int max_matches);

/**
 * owl_sig_match_single - Test a single rule against a buffer
 * @rule:    Rule to test
 * @buf:     Buffer to scan
 * @buf_len: Buffer length
 * @offset:  Output: byte offset of match (if found)
 *
 * Returns true if the pattern was found.
 */
bool owl_sig_match_single(const struct owl_sig_rule *rule,
			  const uint8_t *buf, size_t buf_len,
			  size_t *offset);

#endif /* OWLBEAR_SCANNER_H */
