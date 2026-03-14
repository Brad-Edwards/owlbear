/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * test_events.c - Unit tests for the shared event header
 *
 * Verifies struct sizes, alignment, field offsets, and enum values
 * to ensure the kernel-userspace contract is correct.
 */

#include <stddef.h>
#include <string.h>

#include "test_harness.h"
#include "owlbear_events.h"

/* -------------------------------------------------------------------------
 * Struct size and alignment tests
 * ----------------------------------------------------------------------- */

TEST(event_struct_size) {
	ASSERT_EQ(sizeof(struct owlbear_event), 128);
}

TEST(payload_sizes) {
	ASSERT_EQ(sizeof(struct owl_payload_process), 64);
	ASSERT_EQ(sizeof(struct owl_payload_memory), 64);
	ASSERT_EQ(sizeof(struct owl_payload_module), 64);
	ASSERT_EQ(sizeof(struct owl_payload_arm64), 64);
	ASSERT_EQ(sizeof(struct owl_payload_signature), 64);
}

TEST(header_offset) {
	/* Header should be exactly 64 bytes, payload starts at offset 64 */
	ASSERT_EQ(offsetof(struct owlbear_event, payload), 64);
}

TEST(status_struct_size) {
	/* owl_status should be a nice round size */
	ASSERT_EQ(sizeof(struct owl_status), 32);
}

/* -------------------------------------------------------------------------
 * Event type range tests - verify enum grouping
 * ----------------------------------------------------------------------- */

TEST(event_type_ranges) {
	/* Process events in 0x00xx range */
	ASSERT_TRUE(OWL_EVENT_PROCESS_CREATE >= 0x0000);
	ASSERT_TRUE(OWL_EVENT_PROCESS_CREATE < 0x0100);
	ASSERT_TRUE(OWL_EVENT_PROCESS_EXEC < 0x0100);

	/* Memory events in 0x01xx range */
	ASSERT_TRUE(OWL_EVENT_PTRACE_ATTEMPT >= 0x0100);
	ASSERT_TRUE(OWL_EVENT_PTRACE_ATTEMPT < 0x0200);
	ASSERT_TRUE(OWL_EVENT_EXEC_MMAP < 0x0200);

	/* Integrity events in 0x02xx range */
	ASSERT_TRUE(OWL_EVENT_MODULE_LOAD >= 0x0200);
	ASSERT_TRUE(OWL_EVENT_MODULE_LOAD < 0x0300);

	/* ARM64 events in 0x03xx range */
	ASSERT_TRUE(OWL_EVENT_DEBUG_REG_ACTIVE >= 0x0300);
	ASSERT_TRUE(OWL_EVENT_DEBUG_REG_ACTIVE < 0x0400);

	/* Signature events in 0x04xx range */
	ASSERT_TRUE(OWL_EVENT_SIGNATURE_MATCH >= 0x0400);
	ASSERT_TRUE(OWL_EVENT_SIGNATURE_MATCH < 0x0500);

	/* Health events in 0x05xx range */
	ASSERT_TRUE(OWL_EVENT_HEARTBEAT_MISSED >= 0x0500);
	ASSERT_TRUE(OWL_EVENT_HEARTBEAT_MISSED < 0x0600);
}

/* -------------------------------------------------------------------------
 * Event construction test - verify zero-init and field assignment
 * ----------------------------------------------------------------------- */

TEST(event_zero_init) {
	struct owlbear_event ev = {};

	ASSERT_EQ(ev.timestamp_ns, 0);
	ASSERT_EQ(ev.event_type, 0);
	ASSERT_EQ(ev.severity, 0);
	ASSERT_EQ(ev.source, 0);
	ASSERT_EQ(ev.pid, 0);
	ASSERT_EQ(ev.target_pid, 0);
	ASSERT_EQ(ev.sequence, 0);
	ASSERT_EQ(ev.session_id, 0);
	ASSERT_EQ(ev._reserved, 0);
}

TEST(event_field_assignment) {
	struct owlbear_event ev = {};

	ev.event_type = OWL_EVENT_PTRACE_ATTEMPT;
	ev.severity = OWL_SEV_CRITICAL;
	ev.source = OWL_SRC_KERNEL;
	ev.pid = 1234;
	ev.target_pid = 5678;

	ASSERT_EQ(ev.event_type, OWL_EVENT_PTRACE_ATTEMPT);
	ASSERT_EQ(ev.severity, OWL_SEV_CRITICAL);
	ASSERT_EQ(ev.source, OWL_SRC_KERNEL);
	ASSERT_EQ(ev.pid, 1234);
	ASSERT_EQ(ev.target_pid, 5678);
}

TEST(payload_process) {
	struct owlbear_event ev = {};

	ev.payload.process.parent_pid = 42;
	ev.payload.process.uid = 1000;
	strncpy(ev.payload.process.filename, "/usr/bin/test",
		sizeof(ev.payload.process.filename) - 1);

	ASSERT_EQ(ev.payload.process.parent_pid, 42);
	ASSERT_EQ(ev.payload.process.uid, 1000);
	ASSERT_STR_EQ(ev.payload.process.filename, "/usr/bin/test");
}

TEST(payload_arm64) {
	struct owlbear_event ev = {};

	ev.payload.arm64.expected = 0xDEADBEEFCAFEBABEULL;
	ev.payload.arm64.actual = 0x1234567890ABCDEFULL;
	ev.payload.arm64.register_id = 0x0301;
	strncpy(ev.payload.arm64.description, "SCTLR_EL1 WXN bit cleared",
		sizeof(ev.payload.arm64.description) - 1);

	ASSERT_EQ(ev.payload.arm64.expected, 0xDEADBEEFCAFEBABEULL);
	ASSERT_EQ(ev.payload.arm64.actual, 0x1234567890ABCDEFULL);
	ASSERT_EQ(ev.payload.arm64.register_id, 0x0301);
}

/* -------------------------------------------------------------------------
 * Heartbeat struct tests
 * ----------------------------------------------------------------------- */

TEST(heartbeat_game_size) {
	/* Should be compact for frequent local IPC */
	ASSERT_TRUE(sizeof(struct owl_heartbeat_game) <= 24);
}

TEST(heartbeat_platform_size) {
	/* Larger is OK - sent less frequently over HTTPS */
	ASSERT_TRUE(sizeof(struct owl_heartbeat_platform) <= 160);
}

TEST(platform_response_size) {
	ASSERT_TRUE(sizeof(struct owl_platform_response) <= 16);
}

/* -------------------------------------------------------------------------
 * IOCTL magic number test
 * ----------------------------------------------------------------------- */

TEST(ioctl_definitions) {
	/* Verify ioctl commands are distinct */
	ASSERT_NE(OWL_IOC_SET_TARGET, OWL_IOC_CLEAR_TARGET);
	ASSERT_NE(OWL_IOC_SET_TARGET, OWL_IOC_GET_STATUS);
	ASSERT_NE(OWL_IOC_SET_TARGET, OWL_IOC_SET_MODE);
	ASSERT_NE(OWL_IOC_CLEAR_TARGET, OWL_IOC_GET_STATUS);
	ASSERT_NE(OWL_IOC_CLEAR_TARGET, OWL_IOC_SET_MODE);
	ASSERT_NE(OWL_IOC_GET_STATUS, OWL_IOC_SET_MODE);
}

/* -------------------------------------------------------------------------
 * Test runner
 * ----------------------------------------------------------------------- */

int main(void)
{
	printf("=== Owlbear Event Header Tests ===\n");

	RUN_TEST(event_struct_size);
	RUN_TEST(payload_sizes);
	RUN_TEST(header_offset);
	RUN_TEST(status_struct_size);
	RUN_TEST(event_type_ranges);
	RUN_TEST(event_zero_init);
	RUN_TEST(event_field_assignment);
	RUN_TEST(payload_process);
	RUN_TEST(payload_arm64);
	RUN_TEST(heartbeat_game_size);
	RUN_TEST(heartbeat_platform_size);
	RUN_TEST(platform_response_size);
	RUN_TEST(ioctl_definitions);

	TEST_SUMMARY();
	return test_failures;
}
