// SPDX-License-Identifier: GPL-2.0-only
/*
 * owlbear_integrity.c - Code integrity verification
 *
 * Module enumeration via module_mutex is not available to loadable modules
 * on all kernels (symbol not exported on AL2023 6.1). Module load detection
 * is handled by the kprobe on do_init_module in owlbear_memory.c.
 *
 * Future: .text section hashing of the game binary will be implemented
 * in the userspace daemon (reads /proc/pid/maps + /proc/pid/mem).
 */

#include "owlbear_common.h"

int owl_integrity_init(void)
{
	pr_info("owlbear: integrity checks active (module load via kprobe)\n");
	return 0;
}

void owl_integrity_exit(void)
{
	pr_info("owlbear: integrity checks stopped\n");
}
