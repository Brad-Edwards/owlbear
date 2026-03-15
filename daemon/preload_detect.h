/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * preload_detect.h - LD_PRELOAD detection via /proc/<pid>/environ
 *
 * Scans a process's environment for LD_PRELOAD. Called on exec events
 * to detect library injection before the dynamic linker runs.
 */

#ifndef OWLBEAR_PRELOAD_DETECT_H
#define OWLBEAR_PRELOAD_DETECT_H

#include <stddef.h>
#include <sys/types.h>

/**
 * owl_scan_environ_for_preload - Scan null-separated environ buffer
 * @buf:       Buffer of null-separated KEY=VALUE entries
 * @buf_len:   Length of buffer in bytes
 * @value_out: Output buffer for the LD_PRELOAD value (may be NULL)
 * @value_len: Size of value_out
 *
 * Pure function. Walks null-separated entries looking for "LD_PRELOAD=".
 * Copies the value after '=' to value_out if provided.
 *
 * Returns: 1 found, 0 not found, -1 error (null buf or zero len)
 */
int owl_scan_environ_for_preload(const char *buf, size_t buf_len,
				 char *value_out, size_t value_len);

/**
 * owl_check_preload_env - Check if a process has LD_PRELOAD set
 * @pid:       Process to check
 * @value_out: Output buffer for the LD_PRELOAD value (may be NULL)
 * @value_len: Size of value_out
 *
 * I/O wrapper. Reads /proc/<pid>/environ (up to 64KB), calls scan.
 *
 * Returns: 1 found, 0 not found, -1 error
 */
int owl_check_preload_env(pid_t pid, char *value_out, size_t value_len);

#endif /* OWLBEAR_PRELOAD_DETECT_H */
