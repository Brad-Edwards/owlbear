/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * self_protect.h - Daemon self-protection
 *
 * Detects:
 *   - Kernel module unload (/sys/module/owlbear/ disappears)
 *   - Kernel module ioctl failure (module no longer responsive)
 *   - Daemon ptrace (blocks via prctl)
 *   - eBPF program detach (ring buffer fd check)
 */

#ifndef OWLBEAR_SELF_PROTECT_H
#define OWLBEAR_SELF_PROTECT_H

#include <stdbool.h>

/* Self-protection state */
struct owl_self_protect {
	int  dev_fd;         /* /dev/owlbear fd for ioctl check */
	int  bpf_rb_fd;      /* BPF ring buffer fd for liveness */
	bool module_present;  /* Last known module state */
	bool bpf_attached;    /* Last known BPF state */
};

/**
 * owl_selfprotect_init - Initialize self-protection
 * @sp:     Self-protection context
 * @dev_fd: Open fd to /dev/owlbear
 * @bpf_fd: BPF ring buffer fd (-1 if no BPF)
 *
 * Calls prctl(PR_SET_DUMPABLE, 0) to block ptrace on the daemon.
 * Returns 0 on success.
 */
int owl_selfprotect_init(struct owl_self_protect *sp, int dev_fd, int bpf_fd);

/**
 * owl_selfprotect_watchdog - Periodic self-protection check
 * @sp: Self-protection context
 *
 * Checks:
 *   1. /sys/module/owlbear/ exists
 *   2. OWL_IOC_GET_STATUS ioctl succeeds
 *   3. BPF ring buffer fd is still valid
 *
 * Returns a bitmask:
 *   0x00 — all OK
 *   0x01 — module directory missing
 *   0x02 — ioctl failed
 *   0x04 — BPF detached
 */
int owl_selfprotect_watchdog(struct owl_self_protect *sp);

/**
 * owl_selfprotect_check_module - Check if /sys/module/owlbear/ exists
 *
 * Returns true if the module directory exists.
 * Pure function, testable.
 */
bool owl_selfprotect_check_module(void);

/**
 * owl_selfprotect_check_ioctl - Check if OWL_IOC_GET_STATUS works
 * @dev_fd: Open fd to /dev/owlbear
 *
 * Returns true if the ioctl succeeds.
 */
bool owl_selfprotect_check_ioctl(int dev_fd);

#endif /* OWLBEAR_SELF_PROTECT_H */
