/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * test_sig_loader.c - Tests for signature file parser
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "test_harness.h"
#include "scanner.h"
#include "sig_loader.h"

/* -------------------------------------------------------------------------
 * Line parsing tests
 * ----------------------------------------------------------------------- */

TEST(sig_parse_valid_line) {
	char line[] = "test_rule:4D 5A 90 00";
	struct owl_sig_rule rule;

	int ret = owl_sig_parse_line(line, &rule);
	ASSERT_EQ(ret, 0);
	ASSERT_STR_EQ(rule.name, "test_rule");
	ASSERT_EQ(rule.pattern_len, 4);
	ASSERT_EQ(rule.pattern[0].value, 0x4D);
	ASSERT_EQ(rule.pattern[3].value, 0x00);
}

TEST(sig_parse_comment_line) {
	char line[] = "# this is a comment";
	struct owl_sig_rule rule;

	ASSERT_EQ(owl_sig_parse_line(line, &rule), -1);
}

TEST(sig_parse_empty_line) {
	char line[] = "   \n";
	struct owl_sig_rule rule;

	ASSERT_EQ(owl_sig_parse_line(line, &rule), -1);
}

TEST(sig_parse_no_colon) {
	char line[] = "invalid line without colon";
	struct owl_sig_rule rule;

	ASSERT_EQ(owl_sig_parse_line(line, &rule), -1);
}

TEST(sig_parse_empty_pattern) {
	char line[] = "name:";
	struct owl_sig_rule rule;

	ASSERT_EQ(owl_sig_parse_line(line, &rule), -1);
}

TEST(sig_parse_wildcard_pattern) {
	char line[] = "wild:AA ?? BB";
	struct owl_sig_rule rule;

	int ret = owl_sig_parse_line(line, &rule);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(rule.pattern_len, 3);
	ASSERT_EQ(rule.pattern[0].value, 0xAA);
	ASSERT_TRUE(rule.pattern[1].wildcard);
	ASSERT_EQ(rule.pattern[2].value, 0xBB);
}

/* -------------------------------------------------------------------------
 * File loading tests
 * ----------------------------------------------------------------------- */

TEST(sig_load_file_not_found) {
	struct owl_sig_db db;
	owl_sig_db_init(&db);

	int ret = owl_sig_load_file(&db, "/nonexistent/path");
	ASSERT_EQ(ret, -1);
}

TEST(sig_load_file_with_comments) {
	/* Write a temp file */
	const char *path = "/tmp/owlbear_test_sigs.tmp";
	FILE *f = fopen(path, "w");
	ASSERT_TRUE(f != NULL);

	fprintf(f, "# comment line\n");
	fprintf(f, "\n");
	fprintf(f, "rule1:AA BB CC\n");
	fprintf(f, "# another comment\n");
	fprintf(f, "rule2:DD ?? EE\n");
	fclose(f);

	struct owl_sig_db db;
	owl_sig_db_init(&db);

	int loaded = owl_sig_load_file(&db, path);
	ASSERT_EQ(loaded, 2);
	ASSERT_EQ(db.rule_count, 2);
	ASSERT_STR_EQ(db.rules[0].name, "rule1");
	ASSERT_STR_EQ(db.rules[1].name, "rule2");

	unlink(path);
}

/* -------------------------------------------------------------------------
 * Runner
 * ----------------------------------------------------------------------- */

int main(void)
{
	printf("=== Owlbear Signature Loader Tests ===\n");

	RUN_TEST(sig_parse_valid_line);
	RUN_TEST(sig_parse_comment_line);
	RUN_TEST(sig_parse_empty_line);
	RUN_TEST(sig_parse_no_colon);
	RUN_TEST(sig_parse_empty_pattern);
	RUN_TEST(sig_parse_wildcard_pattern);
	RUN_TEST(sig_load_file_not_found);
	RUN_TEST(sig_load_file_with_comments);

	TEST_SUMMARY();
	return test_failures;
}
