// SPDX-License-Identifier: GPL-2.0-only
/*
 * owlbear_integrity.c - Code integrity verification
 *
 * Module enumeration via module_mutex is not available to loadable modules
 * on all kernels (symbol not exported on AL2023 6.1). Module load detection
 * is handled by the kprobe on do_init_module in owlbear_memory.c.
 *
 * .text section hashing is done in the userspace daemon (reads
 * /proc/pid/maps + /proc/pid/mem) — see daemon/integrity.c.
 *
 * This file adds a kprobe on delete_module to detect module unloads
 * after owlbear is loaded (WP5: self-protection).
 */

#include <linux/kprobes.h>
#include <linux/moduleparam.h>
#include "owlbear_common.h"

/* -------------------------------------------------------------------------
 * Kprobe: delete_module — detect module unloads
 *
 * Fires when any module is being removed. We emit an event so the
 * daemon can detect if owlbear or other security modules are unloaded.
 * ----------------------------------------------------------------------- */

static int owl_delete_module_pre(struct kprobe *kp, struct pt_regs *regs)
{
	pid_t target;

	target = owl_get_target_pid();
	if (!target)
		return 0;

	/*
	 * We can't easily get the module name from delete_module args
	 * in a portable way across kernel versions, so just emit a
	 * generic MODULE_UNKNOWN event. The daemon watchdog will
	 * correlate by checking /sys/module/owlbear/.
	 */
	owl_emit_event(OWL_EVENT_MODULE_UNKNOWN, OWL_SEV_WARN,
		       current->pid, target, current->comm);

	return 0;
}

static struct kprobe kp_delete_module = {
	.symbol_name = "delete_module",
	.pre_handler = owl_delete_module_pre,
};

static bool kprobe_registered;

int owl_integrity_init(void)
{
	int ret;

	ret = register_kprobe(&kp_delete_module);
	if (ret < 0) {
		pr_warn("owlbear: delete_module kprobe registration failed: %d\n",
			ret);
		/* Non-fatal: daemon watchdog still polls /sys/module/ */
	} else {
		kprobe_registered = true;
		pr_info("owlbear: module unload detection active (kprobe)\n");
	}

	pr_info("owlbear: integrity checks active (module load via kprobe, "
		".text hash via daemon)\n");
	return 0;
}

void owl_integrity_exit(void)
{
	if (kprobe_registered) {
		unregister_kprobe(&kp_delete_module);
		kprobe_registered = false;
	}

	pr_info("owlbear: integrity checks stopped\n");
}
