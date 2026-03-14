// SPDX-License-Identifier: GPL-2.0-only
/*
 * owlbear_lsm.bpf.c - BPF LSM hook programs
 *
 * Attaches to Linux Security Module hooks to enforce access control
 * on the protected game process. LSM hooks can return -EPERM to deny
 * operations, providing actual enforcement (not just detection).
 *
 * Hooks:
 *   lsm/ptrace_access_check  — block ptrace on protected PID
 *   lsm/file_open            — block /proc/<pid>/mem access
 *   lsm/mmap_file            — monitor executable mmap in game
 *
 * Requires: CONFIG_BPF_LSM=y in kernel config.
 */

#include "owlbear_common.bpf.h"

/* -------------------------------------------------------------------------
 * LSM: ptrace_access_check
 *
 * Called when a process attempts to ptrace another. If the target is
 * protected and the caller is not whitelisted, deny with -EPERM.
 * ----------------------------------------------------------------------- */

SEC("lsm/ptrace_access_check")
int BPF_PROG(owl_ptrace_check, struct task_struct *child, unsigned int mode)
{
	__u32 child_pid = BPF_CORE_READ(child, tgid);
	__u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

	if (!is_protected(child_pid))
		return 0;

	if (is_allowed(caller_pid))
		return 0;

	emit_event(OWL_EVENT_PTRACE_ATTEMPT, OWL_SEV_CRITICAL,
		   caller_pid, child_pid, "BPF LSM: ptrace blocked");

	return -EPERM;
}

/* -------------------------------------------------------------------------
 * LSM: file_open
 *
 * Called when a file is opened. We check if the file is /proc/<pid>/mem
 * for a protected PID. If so, deny access from non-whitelisted callers.
 *
 * Path checking in BPF is limited — we read the dentry name and check
 * if it equals "mem", then verify the parent directory is a protected PID.
 * ----------------------------------------------------------------------- */

SEC("lsm/file_open")
int BPF_PROG(owl_file_open, struct file *file)
{
	struct dentry *dentry;
	struct dentry *parent;
	struct qstr dname;
	struct qstr parent_name;
	char name_buf[8];
	char parent_buf[16];
	__u32 caller_pid;
	long pid_val;

	dentry = BPF_CORE_READ(file, f_path.dentry);
	if (!dentry)
		return 0;

	/* Check if filename is "mem" */
	dname = BPF_CORE_READ(dentry, d_name);
	bpf_probe_read_kernel_str(name_buf, sizeof(name_buf), dname.name);

	if (name_buf[0] != 'm' || name_buf[1] != 'e' ||
	    name_buf[2] != 'm' || name_buf[3] != '\0')
		return 0;

	/* Get parent directory name (should be the PID) */
	parent = BPF_CORE_READ(dentry, d_parent);
	if (!parent)
		return 0;

	parent_name = BPF_CORE_READ(parent, d_name);
	bpf_probe_read_kernel_str(parent_buf, sizeof(parent_buf),
				  parent_name.name);

	/*
	 * Verify parent's parent is "proc" — this distinguishes
	 * /proc/<pid>/mem from other files named "mem".
	 */
	struct dentry *grandparent = BPF_CORE_READ(parent, d_parent);
	if (!grandparent)
		return 0;

	struct qstr gp_name = BPF_CORE_READ(grandparent, d_name);
	char gp_buf[8];
	bpf_probe_read_kernel_str(gp_buf, sizeof(gp_buf), gp_name.name);

	/* Check path structure: .../proc/<pid>/mem */
	bool is_proc = (gp_buf[0] == 'p' && gp_buf[1] == 'r' &&
			gp_buf[2] == 'o' && gp_buf[3] == 'c');

	/* Also accept /proc root where grandparent is "/" */
	bool is_root = (gp_buf[0] == '/' && gp_buf[1] == '\0');

	if (!is_proc && !is_root)
		return 0;

	/* Parse PID from parent directory name */
	pid_val = 0;
	for (int i = 0; i < 10 && parent_buf[i] >= '0' &&
	     parent_buf[i] <= '9'; i++) {
		pid_val = pid_val * 10 + (parent_buf[i] - '0');
	}

	if (pid_val <= 0)
		return 0;

	__u32 target_pid = (__u32)pid_val;

	if (!is_protected(target_pid))
		return 0;

	caller_pid = bpf_get_current_pid_tgid() >> 32;
	if (is_allowed(caller_pid))
		return 0;

	emit_event(OWL_EVENT_PROC_MEM_ACCESS, OWL_SEV_CRITICAL,
		   caller_pid, target_pid,
		   "BPF LSM: /proc/pid/mem blocked");

	return -EPERM;
}

/* -------------------------------------------------------------------------
 * LSM: mmap_file
 *
 * Called when a file is memory-mapped. We monitor for executable
 * mappings (PROT_EXEC) in the protected process, which could indicate
 * code injection via mmap.
 * ----------------------------------------------------------------------- */

SEC("lsm/mmap_file")
int BPF_PROG(owl_mmap_file, struct file *file, unsigned long reqprot,
	     unsigned long prot, unsigned long flags)
{
	__u32 pid;

	/* Only care about executable mappings */
	if (!(prot & 0x4))  /* PROT_EXEC */
		return 0;

	pid = bpf_get_current_pid_tgid() >> 32;

	if (!is_protected(pid))
		return 0;

	/*
	 * Don't block — executable mmaps are normal (loading shared libs).
	 * Just log for the daemon to correlate with other signals.
	 */
	emit_event(OWL_EVENT_EXEC_MMAP, OWL_SEV_WARN,
		   pid, pid, "BPF LSM: PROT_EXEC mmap");

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
