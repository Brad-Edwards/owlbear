// SPDX-License-Identifier: GPL-2.0-only
/*
 * proc_io.c - Shared /proc filesystem I/O helpers
 *
 * Common routines for reading /proc/<pid>/maps and /proc/<pid>/mem.
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "proc_io.h"

char *owl_read_proc_maps(pid_t pid)
{
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/maps", pid);

	FILE *f = fopen(path, "r");
	if (!f)
		return NULL;

	size_t cap = 4096;
	size_t len = 0;
	char *buf = malloc(cap);
	if (!buf) {
		fclose(f);
		return NULL;
	}

	size_t n;
	while ((n = fread(buf + len, 1, cap - len - 1, f)) > 0) {
		len += n;
		if (len >= cap - 1) {
			cap *= 2;
			char *tmp = realloc(buf, cap);
			if (!tmp) {
				free(buf);
				fclose(f);
				return NULL;
			}
			buf = tmp;
		}
	}

	buf[len] = '\0';
	fclose(f);
	return buf;
}

int owl_read_proc_mem(pid_t pid, uint64_t addr, uint8_t *buf, size_t len)
{
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/mem", pid);

	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	if (lseek(fd, (off_t)addr, SEEK_SET) == (off_t)-1) {
		close(fd);
		return -1;
	}

	size_t total = 0;
	while (total < len) {
		ssize_t n = read(fd, buf + total, len - total);
		if (n <= 0) {
			close(fd);
			return -1;
		}
		total += (size_t)n;
	}

	close(fd);
	return 0;
}
