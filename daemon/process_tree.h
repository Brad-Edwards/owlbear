/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * process_tree.h - Process ancestry tree
 *
 * Open-addressing hash map (linear probing) storing PID -> parent/comm/birth.
 * Fed by fork/exec/exit events. Provides ancestry queries for the
 * correlation engine to detect cheat processes spawned near the game.
 */

#ifndef OWLBEAR_PROCESS_TREE_H
#define OWLBEAR_PROCESS_TREE_H

#include <stdint.h>

#include "owlbear_events.h"

#define OWL_PTREE_CAPACITY  1024
#define OWL_PTREE_MAX_CHAIN 32

struct owl_ptree_node {
	uint32_t pid;           /* 0 = empty slot */
	uint32_t parent_pid;
	uint64_t birth_time;    /* timestamp_ns from CREATE/EXEC event */
	char     comm[16];
};

struct owl_ptree {
	struct owl_ptree_node nodes[OWL_PTREE_CAPACITY];
	uint32_t count;
};

struct owl_ptree_chain {
	uint32_t pids[OWL_PTREE_MAX_CHAIN];
	int      len;
};

/**
 * owl_ptree_init - Zero-initialize the process tree
 * @tree: Tree to initialize
 *
 * Returns 0 on success, -1 on NULL input.
 */
int owl_ptree_init(struct owl_ptree *tree);

/**
 * owl_ptree_destroy - Release resources (no-op for static allocation)
 * @tree: Tree to destroy
 */
void owl_ptree_destroy(struct owl_ptree *tree);

/**
 * owl_ptree_insert - Insert or update a process node
 * @tree:       Process tree
 * @pid:        Process ID (must be > 0)
 * @parent_pid: Parent PID
 * @comm:       Process name (up to 15 chars + NUL)
 * @birth_time: Timestamp in nanoseconds
 *
 * On PID collision with different birth_time, overwrites (PID reuse).
 * Returns 0 on success, -1 on error (NULL tree, pid==0, or table full).
 */
int owl_ptree_insert(struct owl_ptree *tree, uint32_t pid,
		     uint32_t parent_pid, const char *comm,
		     uint64_t birth_time);

/**
 * owl_ptree_remove - Remove a process by PID
 * @tree: Process tree
 * @pid:  PID to remove
 *
 * Uses backward-shift deletion to maintain probe chain integrity.
 * Returns 0 on success, -1 on error or not found.
 */
int owl_ptree_remove(struct owl_ptree *tree, uint32_t pid);

/**
 * owl_ptree_lookup - Find a process node by PID
 * @tree: Process tree
 * @pid:  PID to look up
 *
 * Returns pointer to the node, or NULL if not found.
 */
const struct owl_ptree_node *owl_ptree_lookup(const struct owl_ptree *tree,
					      uint32_t pid);

/**
 * owl_ptree_is_descendant - Check if pid descends from ancestor
 * @tree:     Process tree
 * @pid:      PID to check
 * @ancestor: Potential ancestor PID
 *
 * Walks parent_pid chain up to MAX_CHAIN steps.
 * Returns 1 if descendant, 0 if not, -1 on error.
 */
int owl_ptree_is_descendant(const struct owl_ptree *tree,
			    uint32_t pid, uint32_t ancestor);

/**
 * owl_ptree_get_chain - Build ancestry chain from pid to root
 * @tree:  Process tree
 * @pid:   Starting PID
 * @chain: Output chain (caller-allocated)
 *
 * Fills chain->pids[] from target to root, sets chain->len.
 * Returns 0 on success, -1 on error.
 */
int owl_ptree_get_chain(const struct owl_ptree *tree,
			uint32_t pid, struct owl_ptree_chain *chain);

/**
 * owl_ptree_on_event - Dispatch an event to the process tree
 * @tree: Process tree
 * @ev:   Event to process
 *
 * PROCESS_CREATE: insert(pid, parent_pid, comm, timestamp_ns)
 * PROCESS_EXEC:   update comm if PID exists; else insert
 * PROCESS_EXIT:   remove(pid)
 *
 * Returns 0 on success, -1 on error.
 */
int owl_ptree_on_event(struct owl_ptree *tree,
		       const struct owlbear_event *ev);

#endif /* OWLBEAR_PROCESS_TREE_H */
