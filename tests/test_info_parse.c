/*
 * test_info_parse - Unit tests for game info file parsing
 *
 * Tests the format: "<PID> <hex_addr>\n" used by the game info file.
 * Covers: valid input, missing 0x prefix, trailing whitespace, garbage,
 * negative PID, empty file.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_harness.h"
#include "../game/game_state.h"

/* Parser under test — same logic used in cheats */
static int parse_game_info(const char *path, pid_t *pid, uint64_t *addr)
{
	FILE *f = fopen(path, "r");
	if (!f)
		return -1;

	long p;
	char addr_buf[64];
	if (fscanf(f, "%ld %63s", &p, addr_buf) != 2 || p <= 0) {
		fclose(f);
		return -1;
	}
	fclose(f);

	*pid = (pid_t)p;

	char *endptr;
	errno = 0;
	*addr = strtoull(addr_buf, &endptr, 0);
	if (errno != 0 || (*endptr != '\0' && *endptr != '\n')) {
		return -1;
	}

	return 0;
}

static const char *tmpfile_path = "/tmp/owlbear-test-info.tmp";

static void write_tmp(const char *content)
{
	FILE *f = fopen(tmpfile_path, "w");
	if (content)
		fputs(content, f);
	fclose(f);
}

static void cleanup_tmp(void)
{
	unlink(tmpfile_path);
}

/* -------------------------------------------------------------------------
 * Tests
 * ----------------------------------------------------------------------- */

TEST(valid_format)
{
	write_tmp("1234 0xdeadbeef\n");
	pid_t pid;
	uint64_t addr;
	int rc = parse_game_info(tmpfile_path, &pid, &addr);
	ASSERT_EQ(rc, 0);
	ASSERT_EQ(pid, 1234);
	ASSERT_EQ(addr, 0xdeadbeef);
	cleanup_tmp();
}

TEST(without_0x_prefix)
{
	write_tmp("5678 deadbeef\n");
	pid_t pid;
	uint64_t addr;
	/* base 0 auto-detects; without 0x, strtoul treats as decimal */
	/* "deadbeef" without 0x is not valid decimal — should fail or
	 * be treated as hex by strtoull base 0. Actually base 0 only
	 * accepts 0x prefix for hex. So this should fail. */
	int rc = parse_game_info(tmpfile_path, &pid, &addr);
	/* Without 0x prefix, strtoull base 0 treats as decimal. "deadbeef"
	 * has non-digit chars → parse stops early → endptr != '\0' → fail */
	ASSERT_EQ(rc, -1);
	cleanup_tmp();
}

TEST(with_0x_large_addr)
{
	write_tmp("42 0xFFFFFFFF80000000\n");
	pid_t pid;
	uint64_t addr;
	int rc = parse_game_info(tmpfile_path, &pid, &addr);
	ASSERT_EQ(rc, 0);
	ASSERT_EQ(pid, 42);
	ASSERT_EQ(addr, 0xFFFFFFFF80000000ULL);
	cleanup_tmp();
}

TEST(trailing_whitespace)
{
	write_tmp("999 0xabcd   \n");
	pid_t pid;
	uint64_t addr;
	int rc = parse_game_info(tmpfile_path, &pid, &addr);
	ASSERT_EQ(rc, 0);
	ASSERT_EQ(pid, 999);
	ASSERT_EQ(addr, 0xabcd);
	cleanup_tmp();
}

TEST(garbage_input)
{
	write_tmp("not_a_number garbage\n");
	pid_t pid;
	uint64_t addr;
	int rc = parse_game_info(tmpfile_path, &pid, &addr);
	ASSERT_EQ(rc, -1);
	cleanup_tmp();
}

TEST(negative_pid)
{
	write_tmp("-1 0xdeadbeef\n");
	pid_t pid;
	uint64_t addr;
	int rc = parse_game_info(tmpfile_path, &pid, &addr);
	ASSERT_EQ(rc, -1);
	cleanup_tmp();
}

TEST(empty_file)
{
	write_tmp("");
	pid_t pid;
	uint64_t addr;
	int rc = parse_game_info(tmpfile_path, &pid, &addr);
	ASSERT_EQ(rc, -1);
	cleanup_tmp();
}

TEST(missing_file)
{
	unlink(tmpfile_path);
	pid_t pid;
	uint64_t addr;
	int rc = parse_game_info("/tmp/owlbear-nonexistent-info.tmp", &pid, &addr);
	ASSERT_EQ(rc, -1);
}

int main(void)
{
	printf("test_info_parse\n");

	RUN_TEST(valid_format);
	RUN_TEST(without_0x_prefix);
	RUN_TEST(with_0x_large_addr);
	RUN_TEST(trailing_whitespace);
	RUN_TEST(garbage_input);
	RUN_TEST(negative_pid);
	RUN_TEST(empty_file);
	RUN_TEST(missing_file);

	TEST_SUMMARY();
	return test_failures;
}
