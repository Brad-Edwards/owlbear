// SPDX-License-Identifier: GPL-2.0-only
/*
 * owlbear_process.c - Process lifecycle monitoring and ptrace protection
 *
 * Monitors process creation, execution, and termination using kernel
 * tracepoints. Detects and optionally blocks ptrace attachment to the
 * protected game process using kprobes.
 *
 * Detection coverage:
 *   - Process creation (fork/clone)    -> OWL_EVENT_PROCESS_CREATE
 *   - Process execution (execve)       -> OWL_EVENT_PROCESS_EXEC
 *   - Process termination (exit)       -> OWL_EVENT_PROCESS_EXIT
 *   - Ptrace attachment to target      -> OWL_EVENT_PTRACE_ATTEMPT
 */

#include <linux/sched.h>
#include <linux/tracepoint.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/string.h>
#include <linux/binfmts.h>

#include "owlbear_common.h"

/* -------------------------------------------------------------------------
 * Tracepoint callbacks - process lifecycle
 *
 * We use tracepoints (not kprobes) for process lifecycle because they
 * are stable ABI, lower overhead, and specifically designed for this.
 * ----------------------------------------------------------------------- */

static void owl_trace_process_fork(void *data,
				   struct task_struct *parent,
				   struct task_struct *child)
{
	struct owlbear_event event = {};
	pid_t target;

	target = owl_get_target_pid();

	/*
	 * Only emit events related to the protected process or its children.
	 * Without filtering, fork events on a busy system would flood the ring.
	 */
	if (target == 0)
		return;

	if (parent->tgid != target && child->tgid != target)
		return;

	event.event_type = OWL_EVENT_PROCESS_CREATE;
	event.severity = OWL_SEV_INFO;
	event.pid = child->tgid;
	event.target_pid = target;
	strscpy(event.comm, child->comm, sizeof(event.comm));
	event.payload.process.parent_pid = parent->tgid;
	event.payload.process.uid = __kuid_val(task_uid(child));

	owl_emit_event_full(&event);
}

static void owl_trace_process_exec(void *data,
				   struct task_struct *task,
				   pid_t old_pid,
				   struct linux_binprm *bprm)
{
	struct owlbear_event event = {};
	pid_t target;

	target = owl_get_target_pid();
	if (target == 0)
		return;

	/*
	 * Log all execs when a target is set. Cheat processes launching
	 * near the game are suspicious regardless of PID relationship.
	 * The daemon decides what is relevant.
	 */
	event.event_type = OWL_EVENT_PROCESS_EXEC;
	event.severity = OWL_SEV_INFO;
	event.pid = task->tgid;
	event.target_pid = target;
	strscpy(event.comm, task->comm, sizeof(event.comm));
	event.payload.process.parent_pid = task->real_parent ?
		task->real_parent->tgid : 0;
	event.payload.process.uid = __kuid_val(task_uid(task));

	if (bprm && bprm->filename)
		strscpy(event.payload.process.filename, bprm->filename,
			sizeof(event.payload.process.filename));

	owl_emit_event_full(&event);
}

static void owl_trace_process_exit(void *data, struct task_struct *task)
{
	pid_t target;

	target = owl_get_target_pid();
	if (target == 0)
		return;

	if (task->tgid != target)
		return;

	/*
	 * The protected process is exiting. This is critical: if it
	 * exits unexpectedly, it could mean a cheat killed it.
	 */
	owl_emit_event(OWL_EVENT_PROCESS_EXIT, OWL_SEV_WARN,
		       task->tgid, target, task->comm);

	pr_info("owlbear: protected process %d (%s) exiting\n",
		task->tgid, task->comm);
}

/* -------------------------------------------------------------------------
 * Kprobe on ptrace - detect and optionally block debugger attachment
 *
 * We hook the kernel ptrace access check to detect when any process
 * attempts to ptrace the protected game process. This covers:
 *   - strace / ltrace
 *   - gdb attach
 *   - Custom ptrace-based cheat injectors
 *
 * On ARM64, the kprobe handler receives arguments in pt_regs:
 *   x0 = struct task_struct *child
 *   x1 = unsigned int mode
 * ----------------------------------------------------------------------- */

static struct kprobe owl_ptrace_kp;

static int owl_ptrace_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct task_struct *child;
	pid_t child_pid, target, caller_pid;
	struct owlbear_event event = {};

	/*
	 * ARM64: first argument in x0.
	 * x86_64: first argument in rdi.
	 */
#ifdef CONFIG_ARM64
	child = (struct task_struct *)regs->regs[0];
#else
	child = (struct task_struct *)regs->di;
#endif

	if (IS_ERR_OR_NULL(child))
		return 0;

	child_pid = child->tgid;
	target = owl_get_target_pid();

	if (target == 0 || child_pid != target)
		return 0;

	caller_pid = current->tgid;

	event.event_type = OWL_EVENT_PTRACE_ATTEMPT;
	event.severity = OWL_SEV_CRITICAL;
	event.pid = caller_pid;
	event.target_pid = target;
	strscpy(event.comm, current->comm, sizeof(event.comm));
	event.payload.memory.caller_pid = caller_pid;
	event.payload.memory.access_type = OWL_EVENT_PTRACE_ATTEMPT;
	strscpy(event.payload.memory.caller_comm, current->comm,
		sizeof(event.payload.memory.caller_comm));

	owl_emit_event_full(&event);

	pr_warn("owlbear: ptrace attempt on protected PID %d by %s (PID %d)\n",
		target, current->comm, caller_pid);

	return 0;
}

/* -------------------------------------------------------------------------
 * Tracepoint registration helpers
 *
 * The kernel tracepoint API requires us to look up tracepoints by name
 * and register callbacks. We use for_each_kernel_tracepoint() to find
 * them, since direct symbol access is not always available for modules.
 * ----------------------------------------------------------------------- */

static struct tracepoint *tp_sched_process_fork;
static struct tracepoint *tp_sched_process_exec;
static struct tracepoint *tp_sched_process_exit;

struct tp_lookup {
	const char *name;
	struct tracepoint **tp;
};

static void lookup_tracepoint(struct tracepoint *tp, void *priv)
{
	struct tp_lookup *lookup = priv;

	if (strcmp(tp->name, lookup->name) == 0)
		*lookup->tp = tp;
}

static int find_tracepoints(void)
{
	struct tp_lookup lookups[] = {
		{ "sched_process_fork", &tp_sched_process_fork },
		{ "sched_process_exec", &tp_sched_process_exec },
		{ "sched_process_exit", &tp_sched_process_exit },
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(lookups); i++) {
		for_each_kernel_tracepoint(lookup_tracepoint, &lookups[i]);
		if (!*lookups[i].tp) {
			pr_err("owlbear: tracepoint '%s' not found\n",
			       lookups[i].name);
			return -ENOENT;
		}
	}

	return 0;
}

/* -------------------------------------------------------------------------
 * Subsystem init/exit
 * ----------------------------------------------------------------------- */

int owl_process_init(void)
{
	int ret;

	/* Find tracepoints */
	ret = find_tracepoints();
	if (ret)
		return ret;

	/* Register tracepoint callbacks */
	ret = tracepoint_probe_register(tp_sched_process_fork,
					owl_trace_process_fork, NULL);
	if (ret) {
		pr_err("owlbear: failed to register fork tracepoint: %d\n", ret);
		return ret;
	}

	ret = tracepoint_probe_register(tp_sched_process_exec,
					owl_trace_process_exec, NULL);
	if (ret) {
		pr_err("owlbear: failed to register exec tracepoint: %d\n", ret);
		goto err_fork;
	}

	ret = tracepoint_probe_register(tp_sched_process_exit,
					owl_trace_process_exit, NULL);
	if (ret) {
		pr_err("owlbear: failed to register exit tracepoint: %d\n", ret);
		goto err_exec;
	}

	/* Register ptrace kprobe */
	owl_ptrace_kp.symbol_name = "__ptrace_may_access";
	owl_ptrace_kp.pre_handler = owl_ptrace_pre_handler;

	ret = register_kprobe(&owl_ptrace_kp);
	if (ret) {
		pr_err("owlbear: failed to register ptrace kprobe: %d\n", ret);
		goto err_exit_tp;
	}

	pr_info("owlbear: process monitoring active\n");
	return 0;

err_exit_tp:
	tracepoint_probe_unregister(tp_sched_process_exit,
				    owl_trace_process_exit, NULL);
err_exec:
	tracepoint_probe_unregister(tp_sched_process_exec,
				    owl_trace_process_exec, NULL);
err_fork:
	tracepoint_probe_unregister(tp_sched_process_fork,
				    owl_trace_process_fork, NULL);
	tracepoint_synchronize_unregister();
	return ret;
}

void owl_process_exit(void)
{
	unregister_kprobe(&owl_ptrace_kp);

	if (tp_sched_process_exit)
		tracepoint_probe_unregister(tp_sched_process_exit,
					    owl_trace_process_exit, NULL);
	if (tp_sched_process_exec)
		tracepoint_probe_unregister(tp_sched_process_exec,
					    owl_trace_process_exec, NULL);
	if (tp_sched_process_fork)
		tracepoint_probe_unregister(tp_sched_process_fork,
					    owl_trace_process_fork, NULL);

	/*
	 * Ensure all tracepoint callbacks have completed before we return.
	 * This prevents use-after-free if a callback is running on another
	 * CPU while we unload.
	 */
	tracepoint_synchronize_unregister();

	pr_info("owlbear: process monitoring stopped\n");
}
