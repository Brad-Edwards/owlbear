/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * test_hmac_sha256.c - Tests for HMAC-SHA256 and integrity buffer functions
 */

#include <stdlib.h>
#include <string.h>

#include "test_harness.h"
#include "hmac_sha256.h"
#include "integrity.h"
#include "log.h"

enum owl_log_level g_owl_log_level = OWL_LOG_INFO;

/* Helper: hex string to bytes */
static void hex_to_bytes(const char *hex, uint8_t *out, size_t out_len)
{
	for (size_t i = 0; i < out_len; i++) {
		unsigned int byte;
		sscanf(hex + 2 * i, "%02x", &byte);
		out[i] = (uint8_t)byte;
	}
}

/* -------------------------------------------------------------------------
 * RFC 4231 known-answer tests
 * ----------------------------------------------------------------------- */

TEST(hmac_rfc4231_test1) {
	/* Key = 0x0b * 20, data = "Hi There" */
	uint8_t key[20];
	memset(key, 0x0b, sizeof(key));
	const uint8_t *data = (const uint8_t *)"Hi There";
	uint8_t out[OWL_HMAC_SHA256_LEN];
	uint8_t expected[OWL_HMAC_SHA256_LEN];

	hex_to_bytes("b0344c61d8db38535ca8afceaf0bf12b"
		     "881dc200c9833da726e9376c2e32cff7",
		     expected, OWL_HMAC_SHA256_LEN);

	int ret = owl_hmac_sha256(key, sizeof(key), data, 8, out);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(memcmp(out, expected, OWL_HMAC_SHA256_LEN), 0);
}

TEST(hmac_rfc4231_test2) {
	/* Key = "Jefe", data = "what do ya want for nothing?" */
	const uint8_t *key = (const uint8_t *)"Jefe";
	const uint8_t *data = (const uint8_t *)"what do ya want for nothing?";
	uint8_t out[OWL_HMAC_SHA256_LEN];
	uint8_t expected[OWL_HMAC_SHA256_LEN];

	hex_to_bytes("5bdcc146bf60754e6a042426089575c7"
		     "5a003f089d2739839dec58b964ec3843",
		     expected, OWL_HMAC_SHA256_LEN);

	int ret = owl_hmac_sha256(key, 4, data, 28, out);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(memcmp(out, expected, OWL_HMAC_SHA256_LEN), 0);
}

/* -------------------------------------------------------------------------
 * Edge cases
 * ----------------------------------------------------------------------- */

TEST(hmac_empty_input) {
	uint8_t key[OWL_HMAC_SHA256_LEN];
	memset(key, 0x42, sizeof(key));
	uint8_t out[OWL_HMAC_SHA256_LEN];
	memset(out, 0, sizeof(out));

	int ret = owl_hmac_sha256(key, sizeof(key), NULL, 0, out);
	ASSERT_EQ(ret, 0);

	/* Output should be non-zero (valid HMAC of empty data) */
	int all_zero = 1;
	for (size_t i = 0; i < OWL_HMAC_SHA256_LEN; i++) {
		if (out[i] != 0) {
			all_zero = 0;
			break;
		}
	}
	ASSERT_EQ(all_zero, 0);
}

TEST(hmac_large_input) {
	uint8_t key[OWL_HMAC_SHA256_LEN];
	memset(key, 0xBB, sizeof(key));

	size_t len = 64 * 1024;
	uint8_t *data = malloc(len);
	ASSERT_TRUE(data != NULL);
	memset(data, 0xAA, len);

	uint8_t out[OWL_HMAC_SHA256_LEN];
	int ret = owl_hmac_sha256(key, sizeof(key), data, len, out);
	free(data);
	ASSERT_EQ(ret, 0);
}

TEST(hmac_key_change) {
	const uint8_t data[] = "same data for both";
	uint8_t key1[OWL_HMAC_SHA256_LEN], key2[OWL_HMAC_SHA256_LEN];
	memset(key1, 0x11, sizeof(key1));
	memset(key2, 0x22, sizeof(key2));

	uint8_t out1[OWL_HMAC_SHA256_LEN], out2[OWL_HMAC_SHA256_LEN];
	owl_hmac_sha256(key1, sizeof(key1), data, sizeof(data) - 1, out1);
	owl_hmac_sha256(key2, sizeof(key2), data, sizeof(data) - 1, out2);

	ASSERT_NE(memcmp(out1, out2, OWL_HMAC_SHA256_LEN), 0);
}

TEST(hmac_same_data_same_hash) {
	uint8_t key[OWL_HMAC_SHA256_LEN];
	memset(key, 0xCC, sizeof(key));
	const uint8_t data[] = "deterministic";

	uint8_t out1[OWL_HMAC_SHA256_LEN], out2[OWL_HMAC_SHA256_LEN];
	owl_hmac_sha256(key, sizeof(key), data, sizeof(data) - 1, out1);
	owl_hmac_sha256(key, sizeof(key), data, sizeof(data) - 1, out2);

	ASSERT_EQ(memcmp(out1, out2, OWL_HMAC_SHA256_LEN), 0);
}

TEST(hmac_null_inputs) {
	uint8_t key[OWL_HMAC_SHA256_LEN];
	memset(key, 0xDD, sizeof(key));
	uint8_t data[] = "test";
	uint8_t out[OWL_HMAC_SHA256_LEN];

	ASSERT_EQ(owl_hmac_sha256(NULL, sizeof(key), data, 4, out), -1);
	ASSERT_EQ(owl_hmac_sha256(key, sizeof(key), NULL, 4, out), -1);
	ASSERT_EQ(owl_hmac_sha256(key, sizeof(key), data, 4, NULL), -1);
}

TEST(hmac_generate_key) {
	uint8_t key1[OWL_HMAC_SHA256_LEN] = {0};
	uint8_t key2[OWL_HMAC_SHA256_LEN] = {0};

	ASSERT_EQ(owl_hmac_generate_key(key1, sizeof(key1)), 0);
	ASSERT_EQ(owl_hmac_generate_key(key2, sizeof(key2)), 0);

	/* key should be non-zero */
	int all_zero = 1;
	for (size_t i = 0; i < OWL_HMAC_SHA256_LEN; i++) {
		if (key1[i] != 0) {
			all_zero = 0;
			break;
		}
	}
	ASSERT_EQ(all_zero, 0);

	/* Two generated keys should differ */
	ASSERT_NE(memcmp(key1, key2, OWL_HMAC_SHA256_LEN), 0);
}

/* -------------------------------------------------------------------------
 * Integrity buffer functions
 * ----------------------------------------------------------------------- */

TEST(integrity_hmac_baseline_and_check) {
	struct owl_integrity ctx;
	owl_integrity_init_ctx(&ctx);

	uint8_t buf[256];
	memset(buf, 0x42, sizeof(buf));

	int ret = owl_integrity_baseline_buffer(&ctx, buf, sizeof(buf));
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(ctx.baseline_set, true);

	ret = owl_integrity_check_buffer(&ctx, buf, sizeof(buf));
	ASSERT_EQ(ret, 0);
}

TEST(integrity_hmac_violation) {
	struct owl_integrity ctx;
	owl_integrity_init_ctx(&ctx);

	uint8_t buf[256];
	memset(buf, 0x42, sizeof(buf));

	int ret = owl_integrity_baseline_buffer(&ctx, buf, sizeof(buf));
	ASSERT_EQ(ret, 0);

	/* Modify one byte */
	buf[128] = 0xFF;
	ret = owl_integrity_check_buffer(&ctx, buf, sizeof(buf));
	ASSERT_EQ(ret, 1);
}

/* -------------------------------------------------------------------------
 * Runner
 * ----------------------------------------------------------------------- */

int main(void)
{
	printf("=== Owlbear HMAC-SHA256 Tests ===\n");

	RUN_TEST(hmac_rfc4231_test1);
	RUN_TEST(hmac_rfc4231_test2);
	RUN_TEST(hmac_empty_input);
	RUN_TEST(hmac_large_input);
	RUN_TEST(hmac_key_change);
	RUN_TEST(hmac_same_data_same_hash);
	RUN_TEST(hmac_null_inputs);
	RUN_TEST(hmac_generate_key);
	RUN_TEST(integrity_hmac_baseline_and_check);
	RUN_TEST(integrity_hmac_violation);

	TEST_SUMMARY();
	return test_failures;
}
