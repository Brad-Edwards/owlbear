/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * sig_loader.h - Signature file parser
 *
 * Parses signature files in the format:
 *   RULE_NAME:PATTERN
 *
 * Lines starting with # are comments. Empty lines are ignored.
 * PATTERN is hex bytes separated by spaces, with ?? wildcards.
 */

#ifndef OWLBEAR_SIG_LOADER_H
#define OWLBEAR_SIG_LOADER_H

#include "scanner.h"

/**
 * owl_sig_load_file - Parse a signature file into a signature database
 * @db:   Signature database (must be initialized)
 * @path: Path to the signature file
 *
 * Returns number of rules loaded on success, -1 on file open error.
 * Malformed lines are silently skipped.
 */
int owl_sig_load_file(struct owl_sig_db *db, const char *path);

/**
 * owl_sig_parse_line - Parse a single signature line
 * @line: Input line (may be modified)
 * @rule: Output rule
 *
 * Returns 0 on success, -1 if the line is a comment, empty, or malformed.
 */
int owl_sig_parse_line(char *line, struct owl_sig_rule *rule);

#endif /* OWLBEAR_SIG_LOADER_H */
