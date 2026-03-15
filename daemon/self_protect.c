// SPDX-License-Identifier: GPL-2.0-only
/*
 * self_protect.c - Daemon self-protection
 *
 * Monitors kernel module presence, ioctl responsiveness, and
 * eBPF program attachment. Hardens daemon against ptrace.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "self_protect.h"
#include "owlbear_events.h"

int owl_selfprotect_init(struct owl_self_protect *sp, int dev_fd, int bpf_fd)
{
	if (!sp)
		return -1;

	memset(sp, 0, sizeof(*sp));
	sp->dev_fd = dev_fd;
	sp->bpf_rb_fd = bpf_fd;
	sp->module_present = true;
	sp->bpf_attached = (bpf_fd >= 0);

	/* Block ptrace on this process */
	if (prctl(PR_SET_DUMPABLE, 0) < 0) {
		fprintf(stderr, "owlbeard: prctl(PR_SET_DUMPABLE, 0) failed: %s\n",
			strerror(errno));
		/* Non-fatal */
	} else {
		printf("owlbeard: self-protection: ptrace blocked on daemon\n");
	}

	return 0;
}

bool owl_selfprotect_check_module(void)
{
	struct stat st;
	return stat("/sys/module/owlbear", &st) == 0 && S_ISDIR(st.st_mode);
}

bool owl_selfprotect_check_ioctl(int dev_fd)
{
	if (dev_fd < 0)
		return false;

	struct owl_status status;
	return ioctl(dev_fd, OWL_IOC_GET_STATUS, &status) == 0;
}

int owl_selfprotect_watchdog(struct owl_self_protect *sp)
{
	if (!sp)
		return -1;

	int result = 0;

	/* Check 1: module directory */
	bool mod_present = owl_selfprotect_check_module();
	if (!mod_present && sp->module_present) {
		fprintf(stderr, "owlbeard: [ALERT] kernel module unloaded!\n");
		fflush(stderr);
		printf("owlbeard: [ALERT] kernel module unloaded!\n");
		fflush(stdout);
		result |= 0x01;
	}
	sp->module_present = mod_present;

	/* Check 2: ioctl still works */
	if (mod_present && !owl_selfprotect_check_ioctl(sp->dev_fd)) {
		fprintf(stderr, "owlbeard: [ALERT] kernel module not responding!\n");
		result |= 0x02;
	}

	/* Check 3: BPF ring buffer fd still valid */
	if (sp->bpf_rb_fd >= 0) {
		/* Use fcntl F_GETFD to check if fd is still open */
		if (fcntl(sp->bpf_rb_fd, F_GETFD) < 0) {
			if (sp->bpf_attached) {
				fprintf(stderr, "owlbeard: [ALERT] BPF programs detached!\n");
				result |= 0x04;
			}
			sp->bpf_attached = false;
		}
	}

	return result;
}
