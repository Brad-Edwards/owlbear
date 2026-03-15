/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * test_process_tree.c - Tests for process tree construction
 */

#include <string.h>

#include "test_harness.h"
#include "owlbear_events.h"
#include "process_tree.h"

/* -------------------------------------------------------------------------
 * Basic insert / lookup
 * ----------------------------------------------------------------------- */

TEST(ptree_insert_and_lookup) {
	struct owl_ptree tree;
	owl_ptree_init(&tree);

	ASSERT_EQ(owl_ptree_insert(&tree, 100, 1, "bash", 1000), 0);

	const struct owl_ptree_node *n = owl_ptree_lookup(&tree, 100);
	ASSERT_TRUE(n != NULL);
	ASSERT_EQ(n->pid, 100);
	ASSERT_EQ(n->parent_pid, 1);
	ASSERT_EQ(n->birth_time, 1000);
	ASSERT_STR_EQ(n->comm, "bash");
	ASSERT_EQ(tree.count, 1);

	owl_ptree_destroy(&tree);
}

TEST(ptree_lookup_parent) {
	struct owl_ptree tree;
	owl_ptree_init(&tree);

	owl_ptree_insert(&tree, 1, 0, "init", 100);
	owl_ptree_insert(&tree, 100, 1, "bash", 200);

	const struct owl_ptree_node *child = owl_ptree_lookup(&tree, 100);
	ASSERT_TRUE(child != NULL);
	ASSERT_EQ(child->parent_pid, 1);

	const struct owl_ptree_node *parent = owl_ptree_lookup(&tree, 1);
	ASSERT_TRUE(parent != NULL);
	ASSERT_EQ(parent->pid, 1);

	owl_ptree_destroy(&tree);
}

/* -------------------------------------------------------------------------
 * Ancestry chain
 * ----------------------------------------------------------------------- */

TEST(ptree_get_chain) {
	struct owl_ptree tree;
	owl_ptree_init(&tree);

	owl_ptree_insert(&tree, 1,  0, "init",  100);
	owl_ptree_insert(&tree, 10, 1, "bash",  200);
	owl_ptree_insert(&tree, 20, 10, "sh",   300);
	owl_ptree_insert(&tree, 30, 20, "cheat", 400);

	struct owl_ptree_chain chain;
	ASSERT_EQ(owl_ptree_get_chain(&tree, 30, &chain), 0);
	ASSERT_EQ(chain.len, 4);
	ASSERT_EQ(chain.pids[0], 30);
	ASSERT_EQ(chain.pids[1], 20);
	ASSERT_EQ(chain.pids[2], 10);
	ASSERT_EQ(chain.pids[3], 1);

	owl_ptree_destroy(&tree);
}

TEST(ptree_is_descendant) {
	struct owl_ptree tree;
	owl_ptree_init(&tree);

	owl_ptree_insert(&tree, 1,  0, "init",  100);
	owl_ptree_insert(&tree, 10, 1, "bash",  200);
	owl_ptree_insert(&tree, 20, 10, "sh",   300);
	owl_ptree_insert(&tree, 30, 20, "cheat", 400);

	ASSERT_EQ(owl_ptree_is_descendant(&tree, 30, 1), 1);
	ASSERT_EQ(owl_ptree_is_descendant(&tree, 30, 10), 1);
	ASSERT_EQ(owl_ptree_is_descendant(&tree, 30, 20), 1);
	ASSERT_EQ(owl_ptree_is_descendant(&tree, 30, 999), 0);
	ASSERT_EQ(owl_ptree_is_descendant(&tree, 10, 30), 0);

	owl_ptree_destroy(&tree);
}

/* -------------------------------------------------------------------------
 * Remove / exit
 * ----------------------------------------------------------------------- */

TEST(ptree_remove_on_exit) {
	struct owl_ptree tree;
	owl_ptree_init(&tree);

	owl_ptree_insert(&tree, 100, 1, "bash", 1000);
	ASSERT_EQ(tree.count, 1);

	ASSERT_EQ(owl_ptree_remove(&tree, 100), 0);
	ASSERT_TRUE(owl_ptree_lookup(&tree, 100) == NULL);
	ASSERT_EQ(tree.count, 0);

	owl_ptree_destroy(&tree);
}

/* -------------------------------------------------------------------------
 * Capacity
 * ----------------------------------------------------------------------- */

TEST(ptree_capacity) {
	struct owl_ptree tree;
	owl_ptree_init(&tree);

	for (uint32_t i = 1; i <= OWL_PTREE_CAPACITY; i++)
		ASSERT_EQ(owl_ptree_insert(&tree, i, 0, "proc", i * 10), 0);

	ASSERT_EQ(tree.count, OWL_PTREE_CAPACITY);

	/* 1025th insert must fail */
	ASSERT_EQ(owl_ptree_insert(&tree, OWL_PTREE_CAPACITY + 1, 0,
				    "excess", 99999), -1);

	/* All 1024 still findable */
	for (uint32_t i = 1; i <= OWL_PTREE_CAPACITY; i++)
		ASSERT_TRUE(owl_ptree_lookup(&tree, i) != NULL);

	owl_ptree_destroy(&tree);
}

/* -------------------------------------------------------------------------
 * Null / invalid inputs
 * ----------------------------------------------------------------------- */

TEST(ptree_null_inputs) {
	struct owl_ptree tree;
	struct owl_ptree_chain chain;

	owl_ptree_init(&tree);

	ASSERT_EQ(owl_ptree_init(NULL), -1);
	ASSERT_EQ(owl_ptree_insert(NULL, 1, 0, "x", 0), -1);
	ASSERT_EQ(owl_ptree_insert(&tree, 0, 0, "x", 0), -1);
	ASSERT_EQ(owl_ptree_remove(NULL, 1), -1);
	ASSERT_TRUE(owl_ptree_lookup(NULL, 1) == NULL);
	ASSERT_EQ(owl_ptree_is_descendant(NULL, 1, 0), -1);
	ASSERT_EQ(owl_ptree_get_chain(NULL, 1, &chain), -1);
	ASSERT_EQ(owl_ptree_get_chain(&tree, 1, NULL), -1);
	ASSERT_EQ(owl_ptree_on_event(NULL, NULL), -1);

	owl_ptree_destroy(&tree);
}

/* -------------------------------------------------------------------------
 * Reinsert after exit (PID reuse)
 * ----------------------------------------------------------------------- */

TEST(ptree_reinsert_after_exit) {
	struct owl_ptree tree;
	owl_ptree_init(&tree);

	owl_ptree_insert(&tree, 100, 1, "old_proc", 1000);
	owl_ptree_remove(&tree, 100);
	ASSERT_TRUE(owl_ptree_lookup(&tree, 100) == NULL);

	owl_ptree_insert(&tree, 100, 50, "new_proc", 2000);
	const struct owl_ptree_node *n = owl_ptree_lookup(&tree, 100);
	ASSERT_TRUE(n != NULL);
	ASSERT_EQ(n->parent_pid, 50);
	ASSERT_EQ(n->birth_time, 2000);
	ASSERT_STR_EQ(n->comm, "new_proc");
	ASSERT_EQ(tree.count, 1);

	owl_ptree_destroy(&tree);
}

/* -------------------------------------------------------------------------
 * Runner
 * ----------------------------------------------------------------------- */

int main(void)
{
	printf("=== Owlbear Process Tree Tests ===\n");

	RUN_TEST(ptree_insert_and_lookup);
	RUN_TEST(ptree_lookup_parent);
	RUN_TEST(ptree_get_chain);
	RUN_TEST(ptree_is_descendant);
	RUN_TEST(ptree_remove_on_exit);
	RUN_TEST(ptree_capacity);
	RUN_TEST(ptree_null_inputs);
	RUN_TEST(ptree_reinsert_after_exit);

	TEST_SUMMARY();
	return test_failures;
}
