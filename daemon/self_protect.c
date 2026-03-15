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
#include "log.h"

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
		OWL_WARN("prctl(PR_SET_DUMPABLE, 0) failed: %s", strerror(errno));
		/* Non-fatal */
	} else {
		OWL_INFO("self-protection: ptrace blocked on daemon");
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
		OWL_WARN("[ALERT] kernel module unloaded!");
		result |= 0x01;
	}
	sp->module_present = mod_present;

	/* Check 2: ioctl still works */
	if (mod_present && !owl_selfprotect_check_ioctl(sp->dev_fd)) {
		OWL_WARN("[ALERT] kernel module not responding!");
		result |= 0x02;
	}

	/* Check 3: BPF ring buffer fd still valid */
	if (sp->bpf_rb_fd >= 0) {
		/* Use fcntl F_GETFD to check if fd is still open */
		if (fcntl(sp->bpf_rb_fd, F_GETFD) < 0) {
			if (sp->bpf_attached) {
				OWL_WARN("[ALERT] BPF programs detached!");
				result |= 0x04;
			}
			sp->bpf_attached = false;
		}
	}

	return result;
}
