// SPDX-License-Identifier: GPL-2.0-only
/*
 * process_tree.c - Process ancestry tree
 *
 * Open-addressing hash map with linear probing. Single-threaded
 * (called from the epoll event loop), no locking needed.
 */

#include <string.h>

#include "process_tree.h"

/* -------------------------------------------------------------------------
 * Hash + probe helpers
 * ----------------------------------------------------------------------- */

static inline uint32_t hash_pid(uint32_t pid)
{
	return pid % OWL_PTREE_CAPACITY;
}

/* Find slot index for pid, or first empty slot if not present.
 * Returns -1 if table is full and pid is not found. */
static int find_slot(const struct owl_ptree *tree, uint32_t pid)
{
	uint32_t idx = hash_pid(pid);

	for (uint32_t i = 0; i < OWL_PTREE_CAPACITY; i++) {
		uint32_t probe = (idx + i) % OWL_PTREE_CAPACITY;

		if (tree->nodes[probe].pid == 0)
			return (int)probe;
		if (tree->nodes[probe].pid == pid)
			return (int)probe;
	}

	return -1;  /* full */
}

/* Find slot containing exactly this pid, or -1 */
static int find_exact(const struct owl_ptree *tree, uint32_t pid)
{
	uint32_t idx = hash_pid(pid);

	for (uint32_t i = 0; i < OWL_PTREE_CAPACITY; i++) {
		uint32_t probe = (idx + i) % OWL_PTREE_CAPACITY;

		if (tree->nodes[probe].pid == 0)
			return -1;
		if (tree->nodes[probe].pid == pid)
			return (int)probe;
	}

	return -1;
}

/* -------------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------- */

int owl_ptree_init(struct owl_ptree *tree)
{
	if (!tree)
		return -1;

	memset(tree, 0, sizeof(*tree));
	return 0;
}

void owl_ptree_destroy(struct owl_ptree *tree)
{
	if (tree)
		memset(tree, 0, sizeof(*tree));
}

int owl_ptree_insert(struct owl_ptree *tree, uint32_t pid,
		     uint32_t parent_pid, const char *comm,
		     uint64_t birth_time)
{
	if (!tree || pid == 0)
		return -1;

	int slot = find_slot(tree, pid);
	if (slot < 0)
		return -1;  /* table full */

	int is_new = (tree->nodes[slot].pid == 0);

	if (!is_new && tree->count >= OWL_PTREE_CAPACITY) {
		/* Slot holds same PID — overwrite is fine */
	} else if (is_new && tree->count >= OWL_PTREE_CAPACITY) {
		return -1;  /* truly full */
	}

	tree->nodes[slot].pid = pid;
	tree->nodes[slot].parent_pid = parent_pid;
	tree->nodes[slot].birth_time = birth_time;

	memset(tree->nodes[slot].comm, 0, sizeof(tree->nodes[slot].comm));
	if (comm)
		strncpy(tree->nodes[slot].comm, comm,
			sizeof(tree->nodes[slot].comm) - 1);

	if (is_new)
		tree->count++;

	return 0;
}

int owl_ptree_remove(struct owl_ptree *tree, uint32_t pid)
{
	if (!tree || pid == 0)
		return -1;

	int slot = find_exact(tree, pid);
	if (slot < 0)
		return -1;

	/* Backward-shift deletion: clear the slot, then fix up any
	 * displaced entries in the cluster to maintain probe chains. */
	memset(&tree->nodes[slot], 0, sizeof(tree->nodes[slot]));
	tree->count--;

	uint32_t empty = (uint32_t)slot;

	for (uint32_t i = 1; i < OWL_PTREE_CAPACITY; i++) {
		uint32_t probe = (empty + i) % OWL_PTREE_CAPACITY;

		if (tree->nodes[probe].pid == 0)
			break;  /* end of cluster */

		uint32_t home = hash_pid(tree->nodes[probe].pid);

		/* Check if 'probe' needs to move back to fill 'empty'.
		 * This is true when 'home' is not in (empty, probe] on
		 * the circular table. */
		int needs_shift;
		if (empty <= probe)
			needs_shift = (home <= empty || home > probe);
		else
			needs_shift = (home <= empty && home > probe);

		if (needs_shift) {
			tree->nodes[empty] = tree->nodes[probe];
			memset(&tree->nodes[probe], 0,
			       sizeof(tree->nodes[probe]));
			empty = probe;
		}
	}

	return 0;
}

const struct owl_ptree_node *owl_ptree_lookup(const struct owl_ptree *tree,
					      uint32_t pid)
{
	if (!tree || pid == 0)
		return NULL;

	int slot = find_exact(tree, pid);
	if (slot < 0)
		return NULL;

	return &tree->nodes[slot];
}

int owl_ptree_is_descendant(const struct owl_ptree *tree,
			    uint32_t pid, uint32_t ancestor)
{
	if (!tree)
		return -1;

	uint32_t cur = pid;

	for (int i = 0; i < OWL_PTREE_MAX_CHAIN; i++) {
		if (cur == 0)
			return 0;

		const struct owl_ptree_node *n = owl_ptree_lookup(tree, cur);
		if (!n)
			return 0;

		if (n->parent_pid == ancestor)
			return 1;

		/* Self-loop guard */
		if (n->parent_pid == cur)
			return 0;

		cur = n->parent_pid;
	}

	return 0;
}

int owl_ptree_get_chain(const struct owl_ptree *tree,
			uint32_t pid, struct owl_ptree_chain *chain)
{
	if (!tree || !chain)
		return -1;

	memset(chain, 0, sizeof(*chain));

	uint32_t cur = pid;

	for (int i = 0; i < OWL_PTREE_MAX_CHAIN; i++) {
		if (cur == 0)
			break;

		const struct owl_ptree_node *n = owl_ptree_lookup(tree, cur);
		if (!n)
			break;

		chain->pids[chain->len++] = cur;

		/* Self-loop guard */
		if (n->parent_pid == cur)
			break;

		cur = n->parent_pid;
	}

	return 0;
}

int owl_ptree_on_event(struct owl_ptree *tree,
		       const struct owlbear_event *ev)
{
	if (!tree || !ev)
		return -1;

	switch (ev->event_type) {
	case OWL_EVENT_PROCESS_CREATE:
		return owl_ptree_insert(tree, ev->pid,
					ev->payload.process.parent_pid,
					ev->comm, ev->timestamp_ns);

	case OWL_EVENT_PROCESS_EXEC: {
		/* Update comm if PID exists with same birth_time */
		int slot = find_exact(tree, ev->pid);
		if (slot >= 0 &&
		    tree->nodes[slot].birth_time == ev->timestamp_ns) {
			memset(tree->nodes[slot].comm, 0,
			       sizeof(tree->nodes[slot].comm));
			strncpy(tree->nodes[slot].comm, ev->comm,
				sizeof(tree->nodes[slot].comm) - 1);
			return 0;
		}
		/* PID not found or different birth_time — insert */
		return owl_ptree_insert(tree, ev->pid,
					ev->payload.process.parent_pid,
					ev->comm, ev->timestamp_ns);
	}

	case OWL_EVENT_PROCESS_EXIT:
		return owl_ptree_remove(tree, ev->pid);

	default:
		return 0;  /* ignored event type */
	}
}
