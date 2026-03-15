/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * test_integrity.c - Tests for code integrity verification
 */

#include <string.h>

#include "test_harness.h"
#include "integrity.h"

/* -------------------------------------------------------------------------
 * CRC32 tests
 * ----------------------------------------------------------------------- */

TEST(crc32_empty_buffer) {
	uint32_t crc = owl_crc32(NULL, 0);
	/* CRC32 of empty data is 0x00000000 (our impl returns ~0xFFFFFFFF for NULL) */
	/* With our loop-based impl, len=0 means no iterations: ~0xFFFFFFFF = 0 */
	ASSERT_EQ(crc, 0x00000000);
}

TEST(crc32_known_value) {
	/* "123456789" -> CRC32 = 0xCBF43926 */
	const uint8_t data[] = "123456789";
	uint32_t crc = owl_crc32(data, 9);
	ASSERT_EQ(crc, 0xCBF43926);
}

TEST(crc32_single_byte) {
	const uint8_t data[] = {0x00};
	uint32_t crc = owl_crc32(data, 1);
	/* CRC32 of a single null byte: 0xD202EF8D */
	ASSERT_EQ(crc, 0xD202EF8D);
}

TEST(crc32_same_data_same_hash) {
	const uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF};
	uint32_t crc1 = owl_crc32(data, sizeof(data));
	uint32_t crc2 = owl_crc32(data, sizeof(data));
	ASSERT_EQ(crc1, crc2);
}

TEST(crc32_different_data_different_hash) {
	const uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
	const uint8_t data2[] = {0x01, 0x02, 0x03, 0x05};
	uint32_t crc1 = owl_crc32(data1, sizeof(data1));
	uint32_t crc2 = owl_crc32(data2, sizeof(data2));
	ASSERT_NE(crc1, crc2);
}

/* -------------------------------------------------------------------------
 * Maps parsing tests
 * ----------------------------------------------------------------------- */

TEST(parse_text_segment_rxp) {
	const char *maps =
		"00400000-00410000 r--p 00000000 08:01 123 /usr/bin/game\n"
		"00410000-00450000 r-xp 00010000 08:01 123 /usr/bin/game\n"
		"00450000-00460000 r--p 00050000 08:01 123 /usr/bin/game\n"
		"00460000-00470000 rw-p 00060000 08:01 123 /usr/bin/game\n";

	uint64_t start, size;
	int ret = owl_integrity_parse_text_segment(maps, &start, &size);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(start, 0x00410000);
	ASSERT_EQ(size, 0x00040000);
}

TEST(parse_text_segment_no_rxp) {
	const char *maps =
		"00400000-00410000 r--p 00000000 08:01 123 /usr/bin/game\n"
		"00410000-00450000 rw-p 00010000 08:01 123 /usr/bin/game\n";

	uint64_t start, size;
	int ret = owl_integrity_parse_text_segment(maps, &start, &size);
	ASSERT_EQ(ret, -1);
}

TEST(parse_text_segment_null_input) {
	uint64_t start, size;
	ASSERT_EQ(owl_integrity_parse_text_segment(NULL, &start, &size), -1);
}

/* -------------------------------------------------------------------------
 * Init test
 * ----------------------------------------------------------------------- */

TEST(integrity_init_clears_state) {
	struct owl_integrity ctx;
	ctx.baseline_set = true;
	memset(ctx.baseline_hmac, 0xFF, sizeof(ctx.baseline_hmac));
	memset(ctx.hmac_key, 0xFF, sizeof(ctx.hmac_key));

	owl_integrity_init_ctx(&ctx);
	ASSERT_EQ(ctx.baseline_set, false);
	ASSERT_EQ(ctx.baseline_hmac[0], 0);
	ASSERT_EQ(ctx.baseline_hmac[31], 0);
	ASSERT_EQ(ctx.hmac_key[0], 0);
	ASSERT_EQ(ctx.target_pid, 0);
}

/* -------------------------------------------------------------------------
 * Runner
 * ----------------------------------------------------------------------- */

int main(void)
{
	printf("=== Owlbear Integrity Tests ===\n");

	RUN_TEST(crc32_empty_buffer);
	RUN_TEST(crc32_known_value);
	RUN_TEST(crc32_single_byte);
	RUN_TEST(crc32_same_data_same_hash);
	RUN_TEST(crc32_different_data_different_hash);
	RUN_TEST(parse_text_segment_rxp);
	RUN_TEST(parse_text_segment_no_rxp);
	RUN_TEST(parse_text_segment_null_input);
	RUN_TEST(integrity_init_clears_state);

	TEST_SUMMARY();
	return test_failures;
}
