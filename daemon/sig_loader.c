// SPDX-License-Identifier: GPL-2.0-only
/*
 * sig_loader.c - Signature file parser
 *
 * Parses line-oriented signature files: NAME:PATTERN
 */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "sig_loader.h"

int owl_sig_parse_line(char *line, struct owl_sig_rule *rule)
{
	if (!line || !rule)
		return -1;

	/* Strip trailing newline/whitespace */
	size_t len = strlen(line);
	while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r' ||
			   line[len - 1] == ' ' || line[len - 1] == '\t'))
		line[--len] = '\0';

	/* Skip leading whitespace */
	char *p = line;
	while (*p == ' ' || *p == '\t')
		p++;

	/* Skip empty lines and comments */
	if (*p == '\0' || *p == '#')
		return -1;

	/* Find the colon separator */
	char *colon = strchr(p, ':');
	if (!colon || colon == p)
		return -1;

	/* Extract name */
	*colon = '\0';
	char *name = p;
	char *pattern = colon + 1;

	/* Skip leading whitespace in pattern */
	while (*pattern == ' ' || *pattern == '\t')
		pattern++;

	if (*pattern == '\0')
		return -1;

	return owl_sig_parse_pattern(rule, name, pattern);
}

int owl_sig_load_file(struct owl_sig_db *db, const char *path)
{
	if (!db || !path)
		return -1;

	FILE *f = fopen(path, "r");
	if (!f)
		return -1;

	char line[512];
	int loaded = 0;

	while (fgets(line, sizeof(line), f)) {
		struct owl_sig_rule rule;

		if (owl_sig_parse_line(line, &rule) < 0)
			continue;

		if (owl_sig_db_add(db, &rule) < 0)
			break;  /* Database full */

		loaded++;
	}

	fclose(f);
	return loaded;
}
