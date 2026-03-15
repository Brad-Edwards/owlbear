/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * event_pipeline.h - Event processing pipeline
 *
 * Wires policy engine + scanner + heartbeat into a unified pipeline.
 * For each event: evaluate policy -> enforce action -> log.
 * Periodic scan: read game .text, run signature scanner, emit events.
 */

#ifndef OWLBEAR_EVENT_PIPELINE_H
#define OWLBEAR_EVENT_PIPELINE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#include "owlbear_events.h"
#include "policy.h"
#include "process_tree.h"
#include "scanner.h"

/* Maximum size of game .text to scan (8 MB) */
#define OWL_PIPELINE_MAX_TEXT_SIZE  (8 * 1024 * 1024)

/* Pipeline context */
struct owl_pipeline {
	struct owl_policy *policy;
	struct owl_sig_db *sig_db;
	struct owl_ptree  *ptree;
	pid_t              target_pid;
	bool               enforce;
	FILE              *log_file;

	/* Statistics */
	uint32_t events_processed;
	uint32_t actions_block;
	uint32_t actions_kill;
	uint32_t sig_matches;
};

/**
 * owl_pipeline_init - Initialize the event pipeline
 * @pipe:    Pipeline context
 * @policy:  Policy engine (ownership retained by caller)
 * @sig_db:  Signature database (ownership retained by caller)
 * @ptree:   Process tree (may be NULL; ownership retained by caller)
 * @target:  PID of the protected process
 * @enforce: Whether to take enforcement actions
 * @logf:    Log file (may be NULL for stdout only)
 */
void owl_pipeline_init(struct owl_pipeline *pipe,
		       struct owl_policy *policy,
		       struct owl_sig_db *sig_db,
		       struct owl_ptree *ptree,
		       pid_t target, bool enforce, FILE *logf);

/**
 * owl_pipeline_process - Process a single event through the pipeline
 * @pipe:  Pipeline context
 * @ev:    Event to process
 *
 * Evaluates policy, logs the action, and takes enforcement action
 * (BLOCK logs [ENFORCE], KILL sends SIGKILL to the offending process).
 *
 * Returns the policy action taken.
 */
enum owl_policy_action owl_pipeline_process(struct owl_pipeline *pipe,
					    const struct owlbear_event *ev);

/**
 * owl_pipeline_scan - Run periodic signature scan on game .text
 * @pipe:  Pipeline context
 *
 * Reads /proc/<pid>/maps to find the r-xp text segment, reads it
 * via /proc/<pid>/mem, runs signature scanner, emits events for matches.
 *
 * Returns number of matches found, or -1 on error.
 */
int owl_pipeline_scan(struct owl_pipeline *pipe);

/**
 * owl_pipeline_scan_buffer - Scan a memory buffer for signatures
 * @pipe:       Pipeline context
 * @buf:        Buffer to scan
 * @buf_len:    Buffer length
 * @region_base: Base address of the scanned region (for event reporting)
 *
 * Returns number of matches found.
 * This is a pure function variant useful for testing.
 */
int owl_pipeline_scan_buffer(struct owl_pipeline *pipe,
			     const uint8_t *buf, size_t buf_len,
			     uint64_t region_base);

#endif /* OWLBEAR_EVENT_PIPELINE_H */
