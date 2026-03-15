// SPDX-License-Identifier: GPL-2.0-only
/*
 * event_pipeline.c - Event processing pipeline
 *
 * Processes each event through the policy engine, takes enforcement
 * actions, and runs periodic signature scans on game memory.
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "event_pipeline.h"
#include "preload_detect.h"
#include "process_tree.h"

static void pipeline_check_preload(struct owl_pipeline *pipe,
				   const struct owlbear_event *exec_ev);

/* -------------------------------------------------------------------------
 * Initialization
 * ----------------------------------------------------------------------- */

void owl_pipeline_init(struct owl_pipeline *pipe,
		       struct owl_policy *policy,
		       struct owl_sig_db *sig_db,
		       struct owl_ptree *ptree,
		       pid_t target, bool enforce, FILE *logf)
{
	memset(pipe, 0, sizeof(*pipe));
	pipe->policy = policy;
	pipe->sig_db = sig_db;
	pipe->ptree = ptree;
	pipe->target_pid = target;
	pipe->enforce = enforce;
	pipe->log_file = logf;
}

/* -------------------------------------------------------------------------
 * Event processing
 * ----------------------------------------------------------------------- */

enum owl_policy_action owl_pipeline_process(struct owl_pipeline *pipe,
					    const struct owlbear_event *ev)
{
	if (!pipe || !ev || !pipe->policy)
		return OWL_ACT_OBSERVE;

	pipe->events_processed++;

	enum owl_policy_action action = owl_policy_evaluate(
		pipe->policy, ev->event_type, ev->severity);

	/* In observe-only mode, downgrade enforcement actions to LOG */
	if (!pipe->enforce && action >= OWL_ACT_BLOCK)
		action = OWL_ACT_LOG;

	/* Log the action */
	FILE *out = pipe->log_file ? pipe->log_file : stdout;

	switch (action) {
	case OWL_ACT_BLOCK:
		fprintf(out, "[ENFORCE] [BLOCK] event=0x%04x pid=%u target=%u\n",
			ev->event_type, ev->pid, ev->target_pid);
		fflush(out);
		pipe->actions_block++;
		break;

	case OWL_ACT_KILL:
		fprintf(out, "[ENFORCE] [KILL] event=0x%04x pid=%u target=%u\n",
			ev->event_type, ev->pid, ev->target_pid);
		fflush(out);

		if (ev->pid > 1)
			kill((pid_t)ev->pid, SIGKILL);

		pipe->actions_kill++;
		break;

	case OWL_ACT_LOG:
		fprintf(out, "[LOG] event=0x%04x pid=%u target=%u\n",
			ev->event_type, ev->pid, ev->target_pid);
		fflush(out);
		break;

	case OWL_ACT_OBSERVE:
	default:
		break;
	}

	/* On exec events, check for LD_PRELOAD in the new process's environ */
	if (ev->event_type == OWL_EVENT_PROCESS_EXEC)
		pipeline_check_preload(pipe, ev);

	/* Feed process lifecycle events into the process tree */
	if (pipe->ptree)
		owl_ptree_on_event(pipe->ptree, ev);

	return action;
}

/* -------------------------------------------------------------------------
 * LD_PRELOAD detection on exec events
 * ----------------------------------------------------------------------- */

static void pipeline_check_preload(struct owl_pipeline *pipe,
				   const struct owlbear_event *exec_ev)
{
	char preload_val[256];

	if (exec_ev->pid <= 0)
		return;

	if (owl_check_preload_env((pid_t)exec_ev->pid,
				  preload_val, sizeof(preload_val)) != 1)
		return;

	struct owlbear_event ev;
	struct timespec ts;

	memset(&ev, 0, sizeof(ev));
	clock_gettime(CLOCK_MONOTONIC, &ts);
	ev.timestamp_ns = (uint64_t)ts.tv_sec * 1000000000ULL +
			  (uint64_t)ts.tv_nsec;
	ev.event_type = OWL_EVENT_LIB_UNEXPECTED;
	ev.severity = OWL_SEV_CRITICAL;
	ev.source = OWL_SRC_DAEMON;
	ev.pid = exec_ev->pid;
	ev.target_pid = (uint32_t)pipe->target_pid;
	strncpy(ev.payload.module.name, preload_val,
		sizeof(ev.payload.module.name) - 1);

	owl_pipeline_process(pipe, &ev);
}

/* -------------------------------------------------------------------------
 * Signature scanning - buffer variant (testable)
 * ----------------------------------------------------------------------- */

int owl_pipeline_scan_buffer(struct owl_pipeline *pipe,
			     const uint8_t *buf, size_t buf_len,
			     uint64_t region_base)
{
	if (!pipe || !pipe->sig_db || !buf || buf_len == 0)
		return 0;

	struct owl_sig_match matches[16];
	int found = owl_sig_scan(pipe->sig_db, buf, buf_len,
				 matches, 16);

	for (int i = 0; i < found; i++) {
		pipe->sig_matches++;

		/* Emit a signature match event */
		struct owlbear_event ev;
		struct timespec ts;

		memset(&ev, 0, sizeof(ev));
		clock_gettime(CLOCK_MONOTONIC, &ts);
		ev.timestamp_ns = (uint64_t)ts.tv_sec * 1000000000ULL +
				  (uint64_t)ts.tv_nsec;
		ev.event_type = OWL_EVENT_SIGNATURE_MATCH;
		ev.severity = OWL_SEV_CRITICAL;
		ev.source = OWL_SRC_DAEMON;
		ev.pid = (uint32_t)pipe->target_pid;
		ev.target_pid = (uint32_t)pipe->target_pid;

		strncpy(ev.payload.signature.rule_name,
			matches[i].rule_name,
			sizeof(ev.payload.signature.rule_name) - 1);
		ev.payload.signature.match_offset = matches[i].offset;
		ev.payload.signature.region_base = region_base;

		owl_pipeline_process(pipe, &ev);
	}

	return found;
}

/* -------------------------------------------------------------------------
 * Signature scanning - process memory variant
 * ----------------------------------------------------------------------- */

/*
 * Parse /proc/<pid>/maps to find the first r-xp segment.
 * Returns the start address and size of the text segment.
 */
static int find_text_segment(pid_t pid, uint64_t *start, uint64_t *size)
{
	char path[64];
	char line[512];

	snprintf(path, sizeof(path), "/proc/%d/maps", pid);

	FILE *f = fopen(path, "r");
	if (!f)
		return -1;

	while (fgets(line, sizeof(line), f)) {
		uint64_t addr_start, addr_end;
		char perms[8];

		if (sscanf(line, "%lx-%lx %4s",
			   (unsigned long *)&addr_start,
			   (unsigned long *)&addr_end,
			   perms) != 3)
			continue;

		/* Look for r-xp (read+execute, private) */
		if (perms[0] == 'r' && perms[1] == '-' &&
		    perms[2] == 'x' && perms[3] == 'p') {
			*start = addr_start;
			*size = addr_end - addr_start;
			fclose(f);
			return 0;
		}
	}

	fclose(f);
	return -1;
}

int owl_pipeline_scan(struct owl_pipeline *pipe)
{
	if (!pipe || !pipe->sig_db || pipe->target_pid <= 0)
		return -1;

	if (pipe->sig_db->rule_count == 0)
		return 0;

	uint64_t text_start, text_size;
	if (find_text_segment(pipe->target_pid, &text_start, &text_size) < 0)
		return -1;

	/* Cap scan size */
	if (text_size > OWL_PIPELINE_MAX_TEXT_SIZE)
		text_size = OWL_PIPELINE_MAX_TEXT_SIZE;

	/* Read the segment via /proc/<pid>/mem */
	char mempath[64];
	snprintf(mempath, sizeof(mempath), "/proc/%d/mem", pipe->target_pid);

	int fd = open(mempath, O_RDONLY);
	if (fd < 0)
		return -1;

	uint8_t *buf = malloc(text_size);
	if (!buf) {
		close(fd);
		return -1;
	}

	if (lseek(fd, (off_t)text_start, SEEK_SET) == (off_t)-1) {
		free(buf);
		close(fd);
		return -1;
	}

	ssize_t n = read(fd, buf, text_size);
	close(fd);

	if (n <= 0) {
		free(buf);
		return -1;
	}

	int found = owl_pipeline_scan_buffer(pipe, buf, (size_t)n, text_start);

	free(buf);
	return found;
}
