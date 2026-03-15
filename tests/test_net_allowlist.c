/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * test_net_allowlist.c - Tests for the IP allowlist module
 */

#include <string.h>
#include <arpa/inet.h>

#include "test_harness.h"
#include "net_allowlist.h"

/* -------------------------------------------------------------------------
 * Unit tests
 * ----------------------------------------------------------------------- */

TEST(allowlist_init_zeroes_count) {
	struct owl_net_allowlist al;
	al.count = 99;  /* dirty */

	int ret = owl_net_allowlist_init(&al);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(al.count, 0);
}

TEST(allowlist_add_and_check_found) {
	struct owl_net_allowlist al;
	owl_net_allowlist_init(&al);

	uint32_t ip = inet_addr("10.0.0.1");
	ASSERT_EQ(owl_net_allowlist_add(&al, ip), 0);
	ASSERT_TRUE(owl_net_allowlist_check(&al, ip));
}

TEST(allowlist_check_not_found) {
	struct owl_net_allowlist al;
	owl_net_allowlist_init(&al);

	uint32_t ip = inet_addr("10.0.0.1");
	ASSERT_TRUE(!owl_net_allowlist_check(&al, ip));
}

TEST(allowlist_add_multiple) {
	struct owl_net_allowlist al;
	owl_net_allowlist_init(&al);

	uint32_t ip1 = inet_addr("10.0.0.1");
	uint32_t ip2 = inet_addr("10.0.0.2");
	uint32_t ip3 = inet_addr("10.0.0.3");

	ASSERT_EQ(owl_net_allowlist_add(&al, ip1), 0);
	ASSERT_EQ(owl_net_allowlist_add(&al, ip2), 0);
	ASSERT_EQ(owl_net_allowlist_add(&al, ip3), 0);

	ASSERT_TRUE(owl_net_allowlist_check(&al, ip1));
	ASSERT_TRUE(owl_net_allowlist_check(&al, ip2));
	ASSERT_TRUE(owl_net_allowlist_check(&al, ip3));
	ASSERT_EQ(al.count, 3);
}

TEST(allowlist_full_capacity_rejects) {
	struct owl_net_allowlist al;
	owl_net_allowlist_init(&al);

	/* Fill to max */
	for (int i = 0; i < OWL_NET_ALLOWLIST_MAX; i++) {
		uint32_t ip = htonl(0x0A000001 + (uint32_t)i);
		ASSERT_EQ(owl_net_allowlist_add(&al, ip), 0);
	}

	ASSERT_EQ(al.count, OWL_NET_ALLOWLIST_MAX);

	/* Next add should fail */
	uint32_t overflow_ip = htonl(0x0A000001 + OWL_NET_ALLOWLIST_MAX);
	ASSERT_EQ(owl_net_allowlist_add(&al, overflow_ip), -1);
}

TEST(allowlist_null_inputs) {
	struct owl_net_allowlist al;

	ASSERT_EQ(owl_net_allowlist_init(NULL), -1);
	ASSERT_EQ(owl_net_allowlist_add(NULL, 0x01020304), -1);
	ASSERT_TRUE(!owl_net_allowlist_check(NULL, 0x01020304));

	owl_net_allowlist_init(&al);
	/* remove from NULL should return -1 */
	ASSERT_EQ(owl_net_allowlist_remove(NULL, 0x01020304), -1);
}

TEST(allowlist_duplicate_is_idempotent) {
	struct owl_net_allowlist al;
	owl_net_allowlist_init(&al);

	uint32_t ip = inet_addr("192.168.1.1");
	ASSERT_EQ(owl_net_allowlist_add(&al, ip), 0);
	ASSERT_EQ(owl_net_allowlist_add(&al, ip), 0);
	ASSERT_EQ(al.count, 1);
}

TEST(allowlist_remove_and_recheck) {
	struct owl_net_allowlist al;
	owl_net_allowlist_init(&al);

	uint32_t ip1 = inet_addr("10.0.0.1");
	uint32_t ip2 = inet_addr("10.0.0.2");
	owl_net_allowlist_add(&al, ip1);
	owl_net_allowlist_add(&al, ip2);

	ASSERT_EQ(owl_net_allowlist_remove(&al, ip1), 0);
	ASSERT_TRUE(!owl_net_allowlist_check(&al, ip1));
	ASSERT_TRUE(owl_net_allowlist_check(&al, ip2));
	ASSERT_EQ(al.count, 1);

	/* Removing non-existent IP returns -1 */
	ASSERT_EQ(owl_net_allowlist_remove(&al, ip1), -1);
}

/* -------------------------------------------------------------------------
 * Runner
 * ----------------------------------------------------------------------- */

int main(void)
{
	printf("=== Owlbear Net Allowlist Tests ===\n");

	RUN_TEST(allowlist_init_zeroes_count);
	RUN_TEST(allowlist_add_and_check_found);
	RUN_TEST(allowlist_check_not_found);
	RUN_TEST(allowlist_add_multiple);
	RUN_TEST(allowlist_full_capacity_rejects);
	RUN_TEST(allowlist_null_inputs);
	RUN_TEST(allowlist_duplicate_is_idempotent);
	RUN_TEST(allowlist_remove_and_recheck);

	TEST_SUMMARY();
	return test_failures;
}
