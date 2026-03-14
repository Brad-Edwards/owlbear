/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * test_harness.h - Minimal C test framework
 *
 * Usage:
 *   TEST(test_name) {
 *       ASSERT_EQ(1 + 1, 2);
 *       ASSERT_STR_EQ("hello", "hello");
 *   }
 *
 *   int main(void) {
 *       RUN_TEST(test_name);
 *       TEST_SUMMARY();
 *       return test_failures;
 *   }
 */

#ifndef TEST_HARNESS_H
#define TEST_HARNESS_H

#include <stdio.h>
#include <string.h>

static int test_count __attribute__((unused));
static int test_failures __attribute__((unused));
static int test_current_failed __attribute__((unused));
static const char *test_current_name __attribute__((unused));

#define TEST(name) static void test_##name(void)

#define RUN_TEST(name) do {                                    \
	test_current_name = #name;                             \
	test_current_failed = 0;                               \
	test_count++;                                          \
	test_##name();                                         \
	if (test_current_failed)                               \
		printf("  FAIL: %s\n", #name);                 \
	else                                                   \
		printf("  PASS: %s\n", #name);                 \
} while (0)

#define ASSERT_EQ(actual, expected) do {                       \
	long long _a = (long long)(actual);                    \
	long long _e = (long long)(expected);                  \
	if (_a != _e) {                                        \
		printf("    %s:%d: expected %lld, got %lld\n", \
		       __FILE__, __LINE__, _e, _a);            \
		test_current_failed = 1;                       \
		test_failures++;                               \
		return;                                        \
	}                                                      \
} while (0)

#define ASSERT_NE(actual, not_expected) do {                   \
	long long _a = (long long)(actual);                    \
	long long _ne = (long long)(not_expected);             \
	if (_a == _ne) {                                       \
		printf("    %s:%d: expected != %lld\n",        \
		       __FILE__, __LINE__, _ne);               \
		test_current_failed = 1;                       \
		test_failures++;                               \
		return;                                        \
	}                                                      \
} while (0)

#define ASSERT_TRUE(cond) do {                                 \
	if (!(cond)) {                                         \
		printf("    %s:%d: expected true\n",           \
		       __FILE__, __LINE__);                    \
		test_current_failed = 1;                       \
		test_failures++;                               \
		return;                                        \
	}                                                      \
} while (0)

#define ASSERT_STR_EQ(actual, expected) do {                   \
	if (strcmp((actual), (expected)) != 0) {                \
		printf("    %s:%d: expected \"%s\", "          \
		       "got \"%s\"\n",                         \
		       __FILE__, __LINE__, (expected),          \
		       (actual));                               \
		test_current_failed = 1;                       \
		test_failures++;                               \
		return;                                        \
	}                                                      \
} while (0)

#define TEST_SUMMARY() do {                                    \
	printf("\n%d/%d tests passed\n",                       \
	       test_count - test_failures, test_count);        \
} while (0)

#endif /* TEST_HARNESS_H */
