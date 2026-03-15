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
 *   lsm/file_open            — block /proc/<pid>/mem, /dev/mem, /dev/kmem
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
 * Called when a file is opened. Blocks:
 *   /dev/mem, /dev/kmem — unconditional (physical memory = system-wide threat)
 *   /proc/<pid>/mem     — if PID is protected and caller not whitelisted
 *
 * Path checking in BPF is limited — we read the dentry name and check
 * parent/grandparent to distinguish /dev/mem from /proc/<pid>/mem.
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

	/* Check if filename is "mem" or "kmem" */
	dname = BPF_CORE_READ(dentry, d_name);
	bpf_probe_read_kernel_str(name_buf, sizeof(name_buf), dname.name);

	bool is_mem  = (name_buf[0] == 'm' && name_buf[1] == 'e' &&
			name_buf[2] == 'm' && name_buf[3] == '\0');
	bool is_kmem = (name_buf[0] == 'k' && name_buf[1] == 'm' &&
			name_buf[2] == 'e' && name_buf[3] == 'm' &&
			name_buf[4] == '\0');

	if (!is_mem && !is_kmem)
		return 0;

	/* Get parent directory name */
	parent = BPF_CORE_READ(dentry, d_parent);
	if (!parent)
		return 0;

	parent_name = BPF_CORE_READ(parent, d_name);
	bpf_probe_read_kernel_str(parent_buf, sizeof(parent_buf),
				  parent_name.name);

	/*
	 * /dev/mem or /dev/kmem — unconditional block.
	 * Physical memory access threatens ALL processes.
	 */
	bool is_dev_parent = (parent_buf[0] == 'd' && parent_buf[1] == 'e' &&
			      parent_buf[2] == 'v' && parent_buf[3] == '\0');

	if (is_dev_parent && (is_mem || is_kmem)) {
		caller_pid = bpf_get_current_pid_tgid() >> 32;
		emit_event(OWL_EVENT_DEV_MEM_ACCESS, OWL_SEV_CRITICAL,
			   caller_pid, 0,
			   is_kmem ? "BPF LSM: /dev/kmem blocked"
				   : "BPF LSM: /dev/mem blocked");
		return -EPERM;
	}

	/* Only "mem" is relevant under /proc; kmem handled above */
	if (!is_mem)
		return 0;

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

/* -------------------------------------------------------------------------
 * LSM: file_mprotect
 *
 * Called when a process changes memory protection flags. Detects RW->RX
 * transitions in the protected process, which is a common code injection
 * technique: mmap(RW), write shellcode, mprotect(RX), execute.
 *
 * Observe-only: the JIT compiler legitimately does RW->RX transitions,
 * so we emit an event but do not block.
 * ----------------------------------------------------------------------- */

SEC("lsm/file_mprotect")
int BPF_PROG(owl_file_mprotect, struct vm_area_struct *vma,
	     unsigned long reqprot, unsigned long prot)
{
	__u32 pid;

	/*
	 * Detect RW -> RX: the new protection includes EXEC (0x4) and the
	 * VMA previously had write (0x2) permission.
	 */
	if (!(prot & 0x4))  /* PROT_EXEC not requested */
		return 0;

	pid = bpf_get_current_pid_tgid() >> 32;

	if (!is_protected(pid))
		return 0;

	unsigned long old_flags = BPF_CORE_READ(vma, vm_flags);

	/* VM_WRITE = 0x2 in vm_flags */
	if (!(old_flags & 0x2))
		return 0;

	/*
	 * RW->RX transition in protected process. Don't block —
	 * JIT does this legitimately. Log for correlation.
	 */
	emit_event(OWL_EVENT_MPROTECT_EXEC, OWL_SEV_WARN,
		   pid, pid,
		   "BPF LSM: RW->RX mprotect");

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
