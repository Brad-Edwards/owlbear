/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * test_vdso_integrity.c - Tests for vDSO page integrity verification
 *
 * Tests the pure mapping parser, context initialization, and
 * buffer-based tamper detection without requiring /proc I/O.
 */

#include <string.h>

#include "test_harness.h"
#include "vdso_integrity.h"
#include "log.h"

enum owl_log_level g_owl_log_level = OWL_LOG_INFO;

/* -------------------------------------------------------------------------
 * Pure function: owl_vdso_parse_mapping
 * ----------------------------------------------------------------------- */

TEST(parse_mapping_found) {
	const char *maps =
		"aaaac0000000-aaaac0010000 r-xp 00000000 08:01 123 /usr/bin/game\n"
		"fffff7ff8000-fffff7ffa000 r-xp 00000000 00:00 0   [vdso]\n"
		"fffff7ffa000-fffff7ffb000 r--p 00000000 00:00 0   [vvar]\n";

	uint64_t start = 0, size = 0;
	int ret = owl_vdso_parse_mapping(maps, &start, &size);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(start, 0xfffff7ff8000ULL);
	ASSERT_EQ(size, 0x2000ULL);
}

TEST(parse_mapping_not_found) {
	const char *maps =
		"aaaac0000000-aaaac0010000 r-xp 00000000 08:01 123 /usr/bin/game\n"
		"fffff7ffa000-fffff7ffb000 r--p 00000000 00:00 0   [vvar]\n";

	uint64_t start = 0, size = 0;
	int ret = owl_vdso_parse_mapping(maps, &start, &size);
	ASSERT_EQ(ret, -1);
}

TEST(parse_mapping_null) {
	uint64_t start = 0, size = 0;
	ASSERT_EQ(owl_vdso_parse_mapping(NULL, &start, &size), -1);
}

/* -------------------------------------------------------------------------
 * Stateful context: init
 * ----------------------------------------------------------------------- */

TEST(init_sets_state) {
	struct owl_vdso_integrity ctx;
	memset(&ctx, 0xFF, sizeof(ctx));

	int ret = owl_vdso_integrity_init(&ctx, 999);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(ctx.target_pid, 999);
	ASSERT_EQ(ctx.baseline_set, false);
	ASSERT_EQ(ctx.vdso_start, 0ULL);
	ASSERT_EQ(ctx.vdso_size, 0ULL);
}

/* -------------------------------------------------------------------------
 * Buffer-based tamper detection
 * ----------------------------------------------------------------------- */

TEST(check_buffer_detects_tamper) {
	struct owl_vdso_integrity ctx;
	owl_vdso_integrity_init(&ctx, 1);

	/* Create a fake vDSO page */
	uint8_t page[4096];
	memset(page, 0xAA, sizeof(page));

	/* Baseline */
	int ret = owl_vdso_integrity_baseline_buffer(&ctx, page, sizeof(page));
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(ctx.baseline_set, true);

	/* Verify unmodified — should pass */
	ret = owl_vdso_integrity_check_buffer(&ctx, page, sizeof(page));
	ASSERT_EQ(ret, 0);

	/* Tamper with the page */
	page[42] = 0xBB;

	/* Verify modified — should detect tamper */
	ret = owl_vdso_integrity_check_buffer(&ctx, page, sizeof(page));
	ASSERT_EQ(ret, 1);
}

/* -------------------------------------------------------------------------
 * Runner
 * ----------------------------------------------------------------------- */

int main(void)
{
	printf("=== Owlbear vDSO Integrity Tests ===\n");

	RUN_TEST(parse_mapping_found);
	RUN_TEST(parse_mapping_not_found);
	RUN_TEST(parse_mapping_null);
	RUN_TEST(init_sets_state);
	RUN_TEST(check_buffer_detects_tamper);

	TEST_SUMMARY();
	return test_failures;
}
