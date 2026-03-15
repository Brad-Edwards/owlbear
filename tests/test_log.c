/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * test_log.c - Tests for daemon logging macro system
 *
 * Defines its own g_owl_log_level (header-only, no link to main.o).
 * Uses freopen(tmpfile) to capture stdout/stderr output.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_harness.h"
#include "log.h"

/* Test defines its own global — header-only system, no link dependency */
enum owl_log_level g_owl_log_level = OWL_LOG_INFO;

/* -------------------------------------------------------------------------
 * Helpers: capture stdout/stderr via temporary files
 * ----------------------------------------------------------------------- */

static char captured[1024];

static FILE *orig_stdout;
static FILE *orig_stderr;

static char *capture_stream(FILE **stream, void (*emit)(void))
{
	char tmppath[] = "/tmp/owl_log_test_XXXXXX";
	int fd = mkstemp(tmppath);
	if (fd < 0)
		return NULL;

	fflush(*stream);
	FILE *tmp = fdopen(fd, "w+");
	if (!tmp) {
		close(fd);
		unlink(tmppath);
		return NULL;
	}

	/* Save and redirect */
	FILE *saved = *stream;
	*stream = tmp;

	emit();
	fflush(tmp);

	/* Restore */
	*stream = saved;

	/* Read back */
	rewind(tmp);
	size_t n = fread(captured, 1, sizeof(captured) - 1, tmp);
	captured[n] = '\0';

	fclose(tmp);
	unlink(tmppath);
	return captured;
}

/* -------------------------------------------------------------------------
 * Test 1: OWL_ERR goes to stderr
 * ----------------------------------------------------------------------- */

static void emit_err(void) { OWL_ERR("test error"); }

TEST(err_goes_to_stderr) {
	g_owl_log_level = OWL_LOG_INFO;
	char *out = capture_stream(&stderr, emit_err);
	ASSERT_TRUE(out != NULL);
	ASSERT_TRUE(strstr(out, "test error") != NULL);
}

/* -------------------------------------------------------------------------
 * Test 2: OWL_INFO goes to stdout
 * ----------------------------------------------------------------------- */

static void emit_info(void) { OWL_INFO("test info"); }

TEST(info_goes_to_stdout) {
	g_owl_log_level = OWL_LOG_INFO;
	char *out = capture_stream(&stdout, emit_info);
	ASSERT_TRUE(out != NULL);
	ASSERT_TRUE(strstr(out, "test info") != NULL);
}

/* -------------------------------------------------------------------------
 * Test 3: Level filters INFO when set to WARN
 * ----------------------------------------------------------------------- */

static void emit_info_filtered(void) { OWL_INFO("should not appear"); }

TEST(level_filters_info_when_warn) {
	g_owl_log_level = OWL_LOG_WARN;
	char *out = capture_stream(&stdout, emit_info_filtered);
	ASSERT_TRUE(out != NULL);
	ASSERT_EQ(strlen(out), 0);
}

/* -------------------------------------------------------------------------
 * Test 4: Level shows WARN when set to WARN
 * ----------------------------------------------------------------------- */

static void emit_warn(void) { OWL_WARN("warning msg"); }

TEST(level_shows_warn_when_warn) {
	g_owl_log_level = OWL_LOG_WARN;
	char *out = capture_stream(&stderr, emit_warn);
	ASSERT_TRUE(out != NULL);
	ASSERT_TRUE(strstr(out, "warning msg") != NULL);
}

/* -------------------------------------------------------------------------
 * Test 5: Prefix "owlbeard: " is injected
 * ----------------------------------------------------------------------- */

static void emit_prefix(void) { OWL_INFO("hello"); }

TEST(prefix_injected) {
	g_owl_log_level = OWL_LOG_INFO;
	char *out = capture_stream(&stdout, emit_prefix);
	ASSERT_TRUE(out != NULL);
	ASSERT_TRUE(strncmp(out, "owlbeard: ", 10) == 0);
}

/* -------------------------------------------------------------------------
 * Test 6: Format args are interpolated
 * ----------------------------------------------------------------------- */

static void emit_format(void) { OWL_INFO("x=%d", 42); }

TEST(format_args_interpolated) {
	g_owl_log_level = OWL_LOG_INFO;
	char *out = capture_stream(&stdout, emit_format);
	ASSERT_TRUE(out != NULL);
	ASSERT_STR_EQ(out, "owlbeard: x=42\n");
}

/* -------------------------------------------------------------------------
 * Test 7: OWL_DBG compiles away in release (no OWL_DEBUG defined)
 * ----------------------------------------------------------------------- */

static void emit_dbg(void) { OWL_DBG("debug noise"); }

TEST(dbg_compiles_away_in_release) {
	g_owl_log_level = OWL_LOG_DBG;
	char *out = capture_stream(&stdout, emit_dbg);
	ASSERT_TRUE(out != NULL);
	/* Built without -DOWL_DEBUG, so OWL_DBG is a no-op */
	ASSERT_EQ(strlen(out), 0);
}

/* -------------------------------------------------------------------------
 * Runner
 * ----------------------------------------------------------------------- */

int main(void)
{
	/* Save originals in case capture_stream needs a fallback */
	orig_stdout = stdout;
	orig_stderr = stderr;
	(void)orig_stdout;
	(void)orig_stderr;

	printf("=== Owlbear Log Macro Tests ===\n");

	RUN_TEST(err_goes_to_stderr);
	RUN_TEST(info_goes_to_stdout);
	RUN_TEST(level_filters_info_when_warn);
	RUN_TEST(level_shows_warn_when_warn);
	RUN_TEST(prefix_injected);
	RUN_TEST(format_args_interpolated);
	RUN_TEST(dbg_compiles_away_in_release);

	TEST_SUMMARY();
	return test_failures;
}
