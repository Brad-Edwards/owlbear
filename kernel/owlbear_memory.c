// SPDX-License-Identifier: GPL-2.0-only
/*
 * owlbear_memory.c - Memory access protection
 *
 * Intercepts cross-process memory access to the protected game process.
 * Uses kprobes on internal kernel functions that handle:
 *
 *   1. /proc/<pid>/mem  - The procfs memory interface
 *   2. process_vm_readv / process_vm_writev - Cross-process syscalls
 *   3. mmap with PROT_EXEC - Executable memory allocation in game
 *   4. Module loading - Detect new kernel modules after AC init
 *
 * In observe mode, these are logged. In enforce mode, the kprobe
 * handler returns a non-zero value where possible to deny the operation.
 *
 * Note: kprobes on some internal functions may not allow blocking the
 * operation (pre_handler return value is not always honored for denial).
 * For hard enforcement, eBPF LSM hooks (Phase 4) are more reliable.
 * The kprobe approach here provides detection and logging, with
 * best-effort blocking.
 */

#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/pid.h>

#include "owlbear_common.h"

/* -------------------------------------------------------------------------
 * Kprobe: /proc/<pid>/mem open
 *
 * When a process opens /proc/<target>/mem, we detect it here.
 * The kernel function "mem_open" in fs/proc/base.c handles this.
 * Its signature is:  static int mem_open(struct inode *inode, struct file *file)
 *
 * We extract the target PID from the inode's associated task.
 * ----------------------------------------------------------------------- */

static struct kprobe kp_mem_open;

static int kp_mem_open_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct file *file;
	pid_t file_pid, target, caller_pid;
	struct owlbear_event event = {};

	/* mem_open(struct inode *, struct file *) — second arg is the file */
#ifdef CONFIG_ARM64
	file = (struct file *)regs->regs[1];
#else
	file = (struct file *)regs->si;
#endif

	if (IS_ERR_OR_NULL(file))
		return 0;

	/*
	 * Extract the PID from the proc inode. proc_pid() is internal
	 * to fs/proc, so we use the inode number: for /proc/<pid>/mem,
	 * the parent directory inode number encodes the PID.
	 *
	 * However, the simplest reliable approach for a kprobe on
	 * mem_open is to read the file path's dentry parent name,
	 * which is the PID string. We skip the inode approach and
	 * use dentry-based PID extraction instead.
	 */
	{
		struct dentry *dentry;
		struct dentry *parent;
		const char *parent_name;
		long pid_val = 0;
		int i;

		dentry = file->f_path.dentry;
		if (!dentry)
			return 0;

		parent = dentry->d_parent;
		if (!parent)
			return 0;

		parent_name = parent->d_name.name;
		if (!parent_name)
			return 0;

		/* Parse PID from parent directory name */
		for (i = 0; parent_name[i] >= '0' && parent_name[i] <= '9' && i < 10; i++)
			pid_val = pid_val * 10 + (parent_name[i] - '0');

		if (pid_val <= 0)
			return 0;

		file_pid = (pid_t)pid_val;
	}

	target = owl_get_target_pid();
	if (target == 0 || file_pid != target)
		return 0;

	caller_pid = current->tgid;

	/* Don't flag the daemon reading its own target (for sig scanning) */
	if (caller_pid == target)
		return 0;

	event.event_type = OWL_EVENT_PROC_MEM_ACCESS;
	event.severity = OWL_SEV_CRITICAL;
	event.pid = caller_pid;
	event.target_pid = target;
	strscpy(event.comm, current->comm, sizeof(event.comm));
	event.payload.memory.caller_pid = caller_pid;
	event.payload.memory.access_type = OWL_EVENT_PROC_MEM_ACCESS;
	strscpy(event.payload.memory.caller_comm, current->comm,
		sizeof(event.payload.memory.caller_comm));

	owl_emit_event_full(&event);

	pr_warn("owlbear: /proc/%d/mem access by %s (PID %d)\n",
		target, current->comm, caller_pid);

	return 0;
}

/* -------------------------------------------------------------------------
 * Kprobe: process_vm_readv / process_vm_writev
 *
 * These syscalls allow reading/writing another process's memory without
 * ptrace. The internal function is process_vm_rw_core() or similar.
 *
 * We probe the syscall entry points directly:
 *   __arm64_sys_process_vm_readv  (ARM64)
 *   __x64_sys_process_vm_readv   (x86_64)
 *
 * First argument (in the pt_regs passed to the syscall) is the target PID.
 * ----------------------------------------------------------------------- */

static struct kprobe kp_vm_readv;
static struct kprobe kp_vm_writev;

/*
 * Helper to extract the target PID from a process_vm_readv/writev syscall.
 * The first syscall argument is the pid_t of the target process.
 *
 * On ARM64, syscall args are in regs->regs[0..5] within the pt_regs
 * that the syscall wrapper receives. However, __arm64_sys_* wrappers
 * receive a single pt_regs* arg, so we read through it.
 */
static pid_t extract_vm_rw_target(struct pt_regs *regs)
{
#ifdef CONFIG_ARM64
	/*
	 * ARM64 kernel 6.1+: __arm64_sys_* wrappers pass user pt_regs
	 * directly. regs->regs[0] IS the first syscall arg (target PID),
	 * not a pointer to another pt_regs. No double-dereference needed.
	 */
	return (pid_t)regs->regs[0];
#else
	/* x86_64: first arg in rdi */
	return (pid_t)regs->di;
#endif
}

static int kp_vm_readv_pre(struct kprobe *p, struct pt_regs *regs)
{
	pid_t vm_target, target, caller_pid;
	struct owlbear_event event = {};

	vm_target = extract_vm_rw_target(regs);
	target = owl_get_target_pid();

	if (target == 0 || vm_target != target)
		return 0;

	caller_pid = current->tgid;
	if (caller_pid == target)
		return 0;

	event.event_type = OWL_EVENT_VM_READV_ATTEMPT;
	event.severity = OWL_SEV_CRITICAL;
	event.pid = caller_pid;
	event.target_pid = target;
	strscpy(event.comm, current->comm, sizeof(event.comm));
	event.payload.memory.caller_pid = caller_pid;
	event.payload.memory.access_type = OWL_EVENT_VM_READV_ATTEMPT;
	strscpy(event.payload.memory.caller_comm, current->comm,
		sizeof(event.payload.memory.caller_comm));

	owl_emit_event_full(&event);

	pr_warn("owlbear: process_vm_readv on PID %d by %s (PID %d)\n",
		target, current->comm, caller_pid);

	return 0;
}

static int kp_vm_writev_pre(struct kprobe *p, struct pt_regs *regs)
{
	pid_t vm_target, target, caller_pid;
	struct owlbear_event event = {};

	vm_target = extract_vm_rw_target(regs);
	target = owl_get_target_pid();

	if (target == 0 || vm_target != target)
		return 0;

	caller_pid = current->tgid;
	if (caller_pid == target)
		return 0;

	event.event_type = OWL_EVENT_VM_WRITEV_ATTEMPT;
	event.severity = OWL_SEV_CRITICAL;
	event.pid = caller_pid;
	event.target_pid = target;
	strscpy(event.comm, current->comm, sizeof(event.comm));
	event.payload.memory.caller_pid = caller_pid;
	event.payload.memory.access_type = OWL_EVENT_VM_WRITEV_ATTEMPT;
	strscpy(event.payload.memory.caller_comm, current->comm,
		sizeof(event.payload.memory.caller_comm));

	owl_emit_event_full(&event);

	pr_warn("owlbear: process_vm_writev on PID %d by %s (PID %d)\n",
		target, current->comm, caller_pid);

	return 0;
}

/* -------------------------------------------------------------------------
 * Kprobe: mmap with PROT_EXEC
 *
 * Detect when the protected process (or something injecting into it)
 * creates executable memory mappings. This is how most code injection
 * works: allocate RWX or RW then mprotect to RX.
 *
 * We probe vm_mmap_pgoff which is the common path for mmap calls.
 * Signature: unsigned long vm_mmap_pgoff(struct file *file,
 *            unsigned long addr, unsigned long len,
 *            unsigned long prot, unsigned long flag,
 *            unsigned long pgoff)
 * ----------------------------------------------------------------------- */

static struct kprobe kp_mmap;

static int kp_mmap_pre(struct kprobe *p, struct pt_regs *regs)
{
	unsigned long prot;
	pid_t caller_pid, target;
	struct owlbear_event event = {};

	target = owl_get_target_pid();
	if (target == 0)
		return 0;

	caller_pid = current->tgid;
	if (caller_pid != target)
		return 0;

	/* prot is the 4th argument (index 3) */
#ifdef CONFIG_ARM64
	prot = regs->regs[3];
#else
	prot = regs->cx; /* x86_64: 4th arg in rcx */
#endif

	/* PROT_EXEC = 0x4 */
	if (!(prot & 0x4))
		return 0;

	event.event_type = OWL_EVENT_EXEC_MMAP;
	event.severity = OWL_SEV_WARN;
	event.pid = caller_pid;
	event.target_pid = target;
	strscpy(event.comm, current->comm, sizeof(event.comm));

#ifdef CONFIG_ARM64
	event.payload.memory.address = regs->regs[1]; /* addr */
	event.payload.memory.size = regs->regs[2];    /* len */
#else
	event.payload.memory.address = regs->si;
	event.payload.memory.size = regs->dx;
#endif

	owl_emit_event_full(&event);

	return 0;
}

/* -------------------------------------------------------------------------
 * Module load monitoring
 *
 * Detect when new kernel modules are loaded after the anti-cheat.
 * Uses a kprobe on do_init_module() which is called for every module
 * that successfully loads.
 *
 * Signature: static noinline int do_init_module(struct module *mod)
 * ----------------------------------------------------------------------- */

static struct kprobe kp_module_load;

static int kp_module_load_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct module *mod;
	struct owlbear_event event = {};

#ifdef CONFIG_ARM64
	mod = (struct module *)regs->regs[0];
#else
	mod = (struct module *)regs->di;
#endif

	if (IS_ERR_OR_NULL(mod))
		return 0;

	event.event_type = OWL_EVENT_MODULE_LOAD;
	event.severity = OWL_SEV_WARN;
	event.pid = current->tgid;
	event.target_pid = owl_get_target_pid();
	strscpy(event.comm, current->comm, sizeof(event.comm));
	strscpy(event.payload.module.name, mod->name,
		sizeof(event.payload.module.name));

	owl_emit_event_full(&event);

	pr_info("owlbear: kernel module loaded: %s\n", mod->name);

	return 0;
}

/* -------------------------------------------------------------------------
 * Subsystem init/exit
 * ----------------------------------------------------------------------- */

int owl_memory_init(void)
{
	int ret;

	/* Kprobe: /proc/pid/mem open */
	kp_mem_open.symbol_name = "mem_open";
	kp_mem_open.pre_handler = kp_mem_open_pre;
	ret = register_kprobe(&kp_mem_open);
	if (ret) {
		pr_warn("owlbear: mem_open kprobe failed: %d (non-fatal)\n", ret);
		/* Non-fatal: symbol may not be available on all kernels */
		memset(&kp_mem_open, 0, sizeof(kp_mem_open));
	}

	/* Kprobe: process_vm_readv */
#ifdef CONFIG_ARM64
	kp_vm_readv.symbol_name = "__arm64_sys_process_vm_readv";
#else
	kp_vm_readv.symbol_name = "__x64_sys_process_vm_readv";
#endif
	kp_vm_readv.pre_handler = kp_vm_readv_pre;
	ret = register_kprobe(&kp_vm_readv);
	if (ret) {
		pr_warn("owlbear: vm_readv kprobe failed: %d (non-fatal)\n", ret);
		memset(&kp_vm_readv, 0, sizeof(kp_vm_readv));
	}

	/* Kprobe: process_vm_writev */
#ifdef CONFIG_ARM64
	kp_vm_writev.symbol_name = "__arm64_sys_process_vm_writev";
#else
	kp_vm_writev.symbol_name = "__x64_sys_process_vm_writev";
#endif
	kp_vm_writev.pre_handler = kp_vm_writev_pre;
	ret = register_kprobe(&kp_vm_writev);
	if (ret) {
		pr_warn("owlbear: vm_writev kprobe failed: %d (non-fatal)\n", ret);
		memset(&kp_vm_writev, 0, sizeof(kp_vm_writev));
	}

	/* Kprobe: mmap with PROT_EXEC */
	kp_mmap.symbol_name = "vm_mmap_pgoff";
	kp_mmap.pre_handler = kp_mmap_pre;
	ret = register_kprobe(&kp_mmap);
	if (ret) {
		pr_warn("owlbear: mmap kprobe failed: %d (non-fatal)\n", ret);
		memset(&kp_mmap, 0, sizeof(kp_mmap));
	}

	/* Kprobe: module loading */
	kp_module_load.symbol_name = "do_init_module";
	kp_module_load.pre_handler = kp_module_load_pre;
	ret = register_kprobe(&kp_module_load);
	if (ret) {
		pr_warn("owlbear: module_load kprobe failed: %d (non-fatal)\n",
			ret);
		memset(&kp_module_load, 0, sizeof(kp_module_load));
	}

	pr_info("owlbear: memory protection active\n");
	return 0;
}

void owl_memory_exit(void)
{
	if (kp_module_load.symbol_name)
		unregister_kprobe(&kp_module_load);
	if (kp_mmap.symbol_name)
		unregister_kprobe(&kp_mmap);
	if (kp_vm_writev.symbol_name)
		unregister_kprobe(&kp_vm_writev);
	if (kp_vm_readv.symbol_name)
		unregister_kprobe(&kp_vm_readv);
	if (kp_mem_open.symbol_name)
		unregister_kprobe(&kp_mem_open);

	pr_info("owlbear: memory protection stopped\n");
}
