/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * test_scanner.c - Unit tests for signature scanner (TDD)
 */

#include <string.h>

#include "test_harness.h"
#include "scanner.h"

/* -------------------------------------------------------------------------
 * Pattern parsing
 * ----------------------------------------------------------------------- */

TEST(parse_simple_pattern) {
	struct owl_sig_rule rule;
	int ret = owl_sig_parse_pattern(&rule, "test", "4D 5A 90 00");

	ASSERT_EQ(ret, 0);
	ASSERT_EQ(rule.pattern_len, 4);
	ASSERT_EQ(rule.pattern[0].value, 0x4D);
	ASSERT_EQ(rule.pattern[0].wildcard, false);
	ASSERT_EQ(rule.pattern[1].value, 0x5A);
	ASSERT_EQ(rule.pattern[2].value, 0x90);
	ASSERT_EQ(rule.pattern[3].value, 0x00);
	ASSERT_STR_EQ(rule.name, "test");
}

TEST(parse_wildcard_pattern) {
	struct owl_sig_rule rule;
	int ret = owl_sig_parse_pattern(&rule, "wild", "4D ?? 90 ?? 00");

	ASSERT_EQ(ret, 0);
	ASSERT_EQ(rule.pattern_len, 5);
	ASSERT_EQ(rule.pattern[0].wildcard, false);
	ASSERT_EQ(rule.pattern[1].wildcard, true);
	ASSERT_EQ(rule.pattern[2].wildcard, false);
	ASSERT_EQ(rule.pattern[3].wildcard, true);
	ASSERT_EQ(rule.pattern[4].wildcard, false);
}

TEST(parse_lowercase_hex) {
	struct owl_sig_rule rule;
	int ret = owl_sig_parse_pattern(&rule, "lc", "4d 5a ff");

	ASSERT_EQ(ret, 0);
	ASSERT_EQ(rule.pattern_len, 3);
	ASSERT_EQ(rule.pattern[0].value, 0x4D);
	ASSERT_EQ(rule.pattern[2].value, 0xFF);
}

TEST(parse_empty_fails) {
	struct owl_sig_rule rule;
	int ret = owl_sig_parse_pattern(&rule, "empty", "");

	ASSERT_EQ(ret, -1);
}

TEST(parse_invalid_hex_fails) {
	struct owl_sig_rule rule;
	int ret = owl_sig_parse_pattern(&rule, "bad", "ZZ 00");

	ASSERT_EQ(ret, -1);
}

TEST(parse_single_byte) {
	struct owl_sig_rule rule;
	int ret = owl_sig_parse_pattern(&rule, "one", "FF");

	ASSERT_EQ(ret, 0);
	ASSERT_EQ(rule.pattern_len, 1);
	ASSERT_EQ(rule.pattern[0].value, 0xFF);
}

/* -------------------------------------------------------------------------
 * Matching
 * ----------------------------------------------------------------------- */

TEST(match_exact_at_start) {
	struct owl_sig_rule rule;
	owl_sig_parse_pattern(&rule, "mz", "4D 5A");

	uint8_t buf[] = { 0x4D, 0x5A, 0x00, 0x00 };
	size_t offset = 0;

	ASSERT_TRUE(owl_sig_match_single(&rule, buf, sizeof(buf), &offset));
	ASSERT_EQ(offset, 0);
}

TEST(match_exact_at_offset) {
	struct owl_sig_rule rule;
	owl_sig_parse_pattern(&rule, "pe", "50 45");

	uint8_t buf[] = { 0x00, 0x00, 0x50, 0x45, 0x00 };
	size_t offset = 0;

	ASSERT_TRUE(owl_sig_match_single(&rule, buf, sizeof(buf), &offset));
	ASSERT_EQ(offset, 2);
}

TEST(match_wildcard) {
	struct owl_sig_rule rule;
	owl_sig_parse_pattern(&rule, "wc", "4D ?? 90");

	uint8_t buf1[] = { 0x4D, 0xFF, 0x90 };
	uint8_t buf2[] = { 0x4D, 0x00, 0x90 };
	uint8_t buf3[] = { 0x4D, 0x42, 0x90 };
	size_t offset;

	ASSERT_TRUE(owl_sig_match_single(&rule, buf1, sizeof(buf1), &offset));
	ASSERT_TRUE(owl_sig_match_single(&rule, buf2, sizeof(buf2), &offset));
	ASSERT_TRUE(owl_sig_match_single(&rule, buf3, sizeof(buf3), &offset));
}

TEST(no_match) {
	struct owl_sig_rule rule;
	owl_sig_parse_pattern(&rule, "nm", "DE AD BE EF");

	uint8_t buf[] = { 0x00, 0x11, 0x22, 0x33, 0x44 };
	size_t offset;

	ASSERT_TRUE(!owl_sig_match_single(&rule, buf, sizeof(buf), &offset));
}

TEST(match_at_end) {
	struct owl_sig_rule rule;
	owl_sig_parse_pattern(&rule, "end", "EE FF");

	uint8_t buf[] = { 0x00, 0x00, 0xEE, 0xFF };
	size_t offset = 0;

	ASSERT_TRUE(owl_sig_match_single(&rule, buf, sizeof(buf), &offset));
	ASSERT_EQ(offset, 2);
}

TEST(pattern_longer_than_buffer) {
	struct owl_sig_rule rule;
	owl_sig_parse_pattern(&rule, "long", "AA BB CC DD EE");

	uint8_t buf[] = { 0xAA, 0xBB };
	size_t offset;

	ASSERT_TRUE(!owl_sig_match_single(&rule, buf, sizeof(buf), &offset));
}

/* -------------------------------------------------------------------------
 * Database operations
 * ----------------------------------------------------------------------- */

TEST(db_init_empty) {
	struct owl_sig_db db;
	owl_sig_db_init(&db);

	ASSERT_EQ(db.rule_count, 0);
}

TEST(db_add_and_scan) {
	struct owl_sig_db db;
	owl_sig_db_init(&db);

	struct owl_sig_rule rule;
	owl_sig_parse_pattern(&rule, "test_sig", "DE AD BE EF");
	owl_sig_db_add(&db, &rule);

	ASSERT_EQ(db.rule_count, 1);

	uint8_t buf[] = { 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00 };
	struct owl_sig_match matches[4];

	int found = owl_sig_scan(&db, buf, sizeof(buf), matches, 4);
	ASSERT_EQ(found, 1);
	ASSERT_STR_EQ(matches[0].rule_name, "test_sig");
	ASSERT_EQ(matches[0].offset, 1);
}

TEST(db_multiple_rules_multiple_matches) {
	struct owl_sig_db db;
	owl_sig_db_init(&db);

	struct owl_sig_rule r1, r2;
	owl_sig_parse_pattern(&r1, "sig_a", "AA BB");
	owl_sig_parse_pattern(&r2, "sig_b", "CC DD");
	owl_sig_db_add(&db, &r1);
	owl_sig_db_add(&db, &r2);

	uint8_t buf[] = { 0xAA, 0xBB, 0x00, 0xCC, 0xDD };
	struct owl_sig_match matches[4];

	int found = owl_sig_scan(&db, buf, sizeof(buf), matches, 4);
	ASSERT_EQ(found, 2);
}

TEST(db_scan_no_match) {
	struct owl_sig_db db;
	owl_sig_db_init(&db);

	struct owl_sig_rule rule;
	owl_sig_parse_pattern(&rule, "nope", "FF FF FF");
	owl_sig_db_add(&db, &rule);

	uint8_t buf[] = { 0x00, 0x11, 0x22, 0x33 };
	struct owl_sig_match matches[4];

	int found = owl_sig_scan(&db, buf, sizeof(buf), matches, 4);
	ASSERT_EQ(found, 0);
}

TEST(db_max_matches_respected) {
	struct owl_sig_db db;
	owl_sig_db_init(&db);

	/* Add 3 rules that all match */
	struct owl_sig_rule r1, r2, r3;
	owl_sig_parse_pattern(&r1, "sig1", "AA");
	owl_sig_parse_pattern(&r2, "sig2", "BB");
	owl_sig_parse_pattern(&r3, "sig3", "CC");
	owl_sig_db_add(&db, &r1);
	owl_sig_db_add(&db, &r2);
	owl_sig_db_add(&db, &r3);

	uint8_t buf[] = { 0xAA, 0xBB, 0xCC };
	struct owl_sig_match matches[2];

	/* 3 rules match but max_matches=2 */
	int found = owl_sig_scan(&db, buf, sizeof(buf), matches, 2);
	ASSERT_EQ(found, 2);
}

/* -------------------------------------------------------------------------
 * Runner
 * ----------------------------------------------------------------------- */

int main(void)
{
	printf("=== Owlbear Signature Scanner Tests ===\n");

	RUN_TEST(parse_simple_pattern);
	RUN_TEST(parse_wildcard_pattern);
	RUN_TEST(parse_lowercase_hex);
	RUN_TEST(parse_empty_fails);
	RUN_TEST(parse_invalid_hex_fails);
	RUN_TEST(parse_single_byte);
	RUN_TEST(match_exact_at_start);
	RUN_TEST(match_exact_at_offset);
	RUN_TEST(match_wildcard);
	RUN_TEST(no_match);
	RUN_TEST(match_at_end);
	RUN_TEST(pattern_longer_than_buffer);
	RUN_TEST(db_init_empty);
	RUN_TEST(db_add_and_scan);
	RUN_TEST(db_multiple_rules_multiple_matches);
	RUN_TEST(db_scan_no_match);
	RUN_TEST(db_max_matches_respected);

	TEST_SUMMARY();
	return test_failures;
}
