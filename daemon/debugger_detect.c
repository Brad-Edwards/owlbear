// SPDX-License-Identifier: GPL-2.0-only
/*
 * debugger_detect.c - TracerPid polling for debugger detection
 *
 * Parses /proc/<pid>/status for the TracerPid field to detect
 * attached debuggers. Complements eBPF LSM ptrace hooks.
 */

#include <stdio.h>
#include <string.h>

#include "debugger_detect.h"

int owl_debugger_detect_init(struct owl_debugger_detect *dd, pid_t target)
{
	if (!dd)
		return -1;

	memset(dd, 0, sizeof(*dd));
	dd->target_pid = target;
	dd->last_tracer = 0;

	return 0;
}

int owl_check_tracer_pid(pid_t pid)
{
	char path[64];
	char line[256];
	FILE *fp;
	int tracer = -1;

	if (pid <= 0)
		return -1;

	snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);

	fp = fopen(path, "r");
	if (!fp)
		return -1;

	while (fgets(line, sizeof(line), fp)) {
		if (strncmp(line, "TracerPid:", 10) == 0) {
			if (sscanf(line + 10, "%d", &tracer) != 1)
				tracer = -1;
			break;
		}
	}

	fclose(fp);
	return tracer;
}

int owl_debugger_detect_check(struct owl_debugger_detect *dd)
{
	if (!dd)
		return -1;

	int tracer = owl_check_tracer_pid(dd->target_pid);
	if (tracer < 0)
		return -1;

	int result = 0;

	/* Detect 0 -> nonzero transition (debugger newly attached) */
	if (tracer != 0 && dd->last_tracer == 0)
		result = 0x01;

	dd->last_tracer = tracer;
	return result;
}
