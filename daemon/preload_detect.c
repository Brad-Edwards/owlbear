// SPDX-License-Identifier: GPL-2.0-only
/*
 * preload_detect.c - LD_PRELOAD detection via /proc/<pid>/environ
 *
 * Scans a process's null-separated environment block for the
 * LD_PRELOAD variable. Used by the event pipeline on exec events.
 */

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "preload_detect.h"

#define LD_PRELOAD_PREFIX    "LD_PRELOAD="
#define LD_PRELOAD_PREFIX_LEN 11
#define ENVIRON_MAX_SIZE     (64 * 1024)

int owl_scan_environ_for_preload(const char *buf, size_t buf_len,
				 char *value_out, size_t value_len)
{
	if (!buf || buf_len == 0)
		return -1;

	const char *pos = buf;
	const char *end = buf + buf_len;

	while (pos < end) {
		size_t entry_len = strnlen(pos, (size_t)(end - pos));

		if (entry_len >= LD_PRELOAD_PREFIX_LEN &&
		    strncmp(pos, LD_PRELOAD_PREFIX, LD_PRELOAD_PREFIX_LEN) == 0) {
			if (value_out && value_len > 0) {
				const char *val = pos + LD_PRELOAD_PREFIX_LEN;
				size_t vlen = entry_len - LD_PRELOAD_PREFIX_LEN;
				if (vlen >= value_len)
					vlen = value_len - 1;
				memcpy(value_out, val, vlen);
				value_out[vlen] = '\0';
			}
			return 1;
		}

		pos += entry_len + 1;
	}

	return 0;
}

int owl_check_preload_env(pid_t pid, char *value_out, size_t value_len)
{
	if (pid <= 0)
		return -1;

	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/environ", (int)pid);

	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	char buf[ENVIRON_MAX_SIZE];
	ssize_t n = read(fd, buf, sizeof(buf));
	close(fd);

	if (n <= 0)
		return -1;

	return owl_scan_environ_for_preload(buf, (size_t)n, value_out, value_len);
}
