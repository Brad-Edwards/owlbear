/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * test_bpf_loader.c - Tests for BPF event conversion and map helpers
 *
 * Tests the pure functions in bpf_loader that don't require actual
 * BPF infrastructure. The conversion logic and degradation paths
 * are fully testable without root or CONFIG_BPF_LSM.
 */

#include <string.h>

#include "test_harness.h"
#include "owlbear_events.h"
#include "bpf_loader.h"

/* -------------------------------------------------------------------------
 * BPF event structure — matches owlbear_common.bpf.h
 * ----------------------------------------------------------------------- */

struct test_bpf_event {
	uint64_t timestamp_ns;
	uint32_t event_type;
	uint32_t severity;
	uint32_t pid;
	uint32_t target_pid;
	char     comm[16];
	char     detail[48];
};

/* -------------------------------------------------------------------------
 * Conversion tests
 * ----------------------------------------------------------------------- */

TEST(bpf_convert_ptrace_event) {
	struct test_bpf_event bev;
	struct owlbear_event out;

	memset(&bev, 0, sizeof(bev));
	bev.timestamp_ns = 1234567890ULL;
	bev.event_type = OWL_EVENT_PTRACE_ATTEMPT;
	bev.severity = OWL_SEV_CRITICAL;
	bev.pid = 100;
	bev.target_pid = 200;
	strncpy(bev.comm, "cheat_proc", sizeof(bev.comm));
	strncpy(bev.detail, "BPF LSM: ptrace blocked", sizeof(bev.detail));

	int ret = owl_bpf_event_convert(&bev, sizeof(bev), &out);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(out.timestamp_ns, 1234567890ULL);
	ASSERT_EQ(out.event_type, OWL_EVENT_PTRACE_ATTEMPT);
	ASSERT_EQ(out.severity, OWL_SEV_CRITICAL);
	ASSERT_EQ(out.source, OWL_SRC_EBPF);
	ASSERT_EQ(out.pid, 100);
	ASSERT_EQ(out.target_pid, 200);
	ASSERT_EQ(out.payload.memory.caller_pid, 100);
}

TEST(bpf_convert_module_load_event) {
	struct test_bpf_event bev;
	struct owlbear_event out;

	memset(&bev, 0, sizeof(bev));
	bev.event_type = OWL_EVENT_MODULE_LOAD;
	bev.severity = OWL_SEV_WARN;
	bev.pid = 50;
	strncpy(bev.detail, "evil_module", sizeof(bev.detail));

	int ret = owl_bpf_event_convert(&bev, sizeof(bev), &out);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(out.event_type, OWL_EVENT_MODULE_LOAD);
	ASSERT_STR_EQ(out.payload.module.name, "evil_module");
}

TEST(bpf_convert_vm_readv_event) {
	struct test_bpf_event bev;
	struct owlbear_event out;

	memset(&bev, 0, sizeof(bev));
	bev.event_type = OWL_EVENT_VM_READV_ATTEMPT;
	bev.severity = OWL_SEV_CRITICAL;
	bev.pid = 300;
	bev.target_pid = 400;
	strncpy(bev.comm, "mem_reader", sizeof(bev.comm));

	int ret = owl_bpf_event_convert(&bev, sizeof(bev), &out);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(out.payload.memory.caller_pid, 300);
}

TEST(bpf_convert_mprotect_event) {
	struct test_bpf_event bev;
	struct owlbear_event out;

	memset(&bev, 0, sizeof(bev));
	bev.event_type = OWL_EVENT_MPROTECT_EXEC;
	bev.severity = OWL_SEV_WARN;
	bev.pid = 500;
	bev.target_pid = 500;

	int ret = owl_bpf_event_convert(&bev, sizeof(bev), &out);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(out.event_type, OWL_EVENT_MPROTECT_EXEC);
	ASSERT_EQ(out.payload.memory.caller_pid, 500);
}

TEST(bpf_convert_dev_mem_access_event) {
	struct test_bpf_event bev;
	struct owlbear_event out;

	memset(&bev, 0, sizeof(bev));
	bev.event_type = OWL_EVENT_DEV_MEM_ACCESS;
	bev.severity = OWL_SEV_CRITICAL;
	bev.pid = 600;
	bev.target_pid = 0;
	strncpy(bev.comm, "dev_mem_read", sizeof(bev.comm));
	strncpy(bev.detail, "BPF LSM: /dev/mem blocked", sizeof(bev.detail));

	int ret = owl_bpf_event_convert(&bev, sizeof(bev), &out);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(out.event_type, OWL_EVENT_DEV_MEM_ACCESS);
	ASSERT_EQ(out.severity, OWL_SEV_CRITICAL);
	ASSERT_EQ(out.source, OWL_SRC_EBPF);
	ASSERT_EQ(out.pid, 600);
	ASSERT_EQ(out.target_pid, 0);
	ASSERT_EQ(out.payload.memory.caller_pid, 600);
}

TEST(bpf_convert_null_input_fails) {
	struct owlbear_event out;

	ASSERT_EQ(owl_bpf_event_convert(NULL, 0, &out), -1);
}

TEST(bpf_convert_null_output_fails) {
	struct test_bpf_event bev;
	memset(&bev, 0, sizeof(bev));

	ASSERT_EQ(owl_bpf_event_convert(&bev, sizeof(bev), NULL), -1);
}

TEST(bpf_convert_too_small_fails) {
	char small[4] = {0};
	struct owlbear_event out;

	ASSERT_EQ(owl_bpf_event_convert(small, sizeof(small), &out), -1);
}

TEST(bpf_convert_unknown_type_uses_raw) {
	struct test_bpf_event bev;
	struct owlbear_event out;

	memset(&bev, 0, sizeof(bev));
	bev.event_type = 0xFFFF;
	bev.detail[0] = 'X';
	bev.detail[1] = 'Y';

	int ret = owl_bpf_event_convert(&bev, sizeof(bev), &out);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(out.event_type, 0xFFFF);
	ASSERT_EQ(out.payload.raw[0], 'X');
	ASSERT_EQ(out.payload.raw[1], 'Y');
}

/* -------------------------------------------------------------------------
 * Network event conversion tests
 * ----------------------------------------------------------------------- */

TEST(bpf_convert_net_connect_event) {
	struct test_bpf_event bev;
	struct owlbear_event out;

	memset(&bev, 0, sizeof(bev));
	bev.timestamp_ns = 9999ULL;
	bev.event_type = OWL_EVENT_NET_CONNECT;
	bev.severity = OWL_SEV_WARN;
	bev.pid = 700;
	bev.target_pid = 700;
	strncpy(bev.comm, "game_proc", sizeof(bev.comm));

	/* Pack detail: dst_addr(4) + dst_port(2) + proto(2) + bytes(8) */
	uint32_t dst_addr = 0xC0A80101;  /* 192.168.1.1 in network order */
	uint16_t dst_port = 0x5000;      /* port in network order */
	uint16_t proto = 6;              /* TCP */
	uint64_t bytes_val = 0;          /* connect: 0 bytes */

	memcpy(bev.detail + 0, &dst_addr, 4);
	memcpy(bev.detail + 4, &dst_port, 2);
	memcpy(bev.detail + 6, &proto, 2);
	memcpy(bev.detail + 8, &bytes_val, 8);

	int ret = owl_bpf_event_convert(&bev, sizeof(bev), &out);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(out.event_type, OWL_EVENT_NET_CONNECT);
	ASSERT_EQ(out.severity, OWL_SEV_WARN);
	ASSERT_EQ(out.source, OWL_SRC_EBPF);
	ASSERT_EQ(out.pid, 700);
	ASSERT_EQ(out.payload.network.dst_addr, dst_addr);
	ASSERT_EQ(out.payload.network.dst_port, dst_port);
	ASSERT_EQ(out.payload.network.protocol, 6);
	ASSERT_EQ(out.payload.network.bytes, 0);
}

TEST(bpf_convert_net_send_event) {
	struct test_bpf_event bev;
	struct owlbear_event out;

	memset(&bev, 0, sizeof(bev));
	bev.timestamp_ns = 8888ULL;
	bev.event_type = OWL_EVENT_NET_SEND;
	bev.severity = OWL_SEV_WARN;
	bev.pid = 800;
	bev.target_pid = 800;
	strncpy(bev.comm, "cheat_udp", sizeof(bev.comm));

	uint32_t dst_addr = 0x636363C0;  /* 192.99.99.99 */
	uint16_t dst_port = 0x697A;      /* 31337 in network order */
	uint16_t proto = 17;             /* UDP */
	uint64_t bytes_val = 256;

	memcpy(bev.detail + 0, &dst_addr, 4);
	memcpy(bev.detail + 4, &dst_port, 2);
	memcpy(bev.detail + 6, &proto, 2);
	memcpy(bev.detail + 8, &bytes_val, 8);

	int ret = owl_bpf_event_convert(&bev, sizeof(bev), &out);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(out.event_type, OWL_EVENT_NET_SEND);
	ASSERT_EQ(out.payload.network.dst_addr, dst_addr);
	ASSERT_EQ(out.payload.network.dst_port, dst_port);
	ASSERT_EQ(out.payload.network.protocol, 17);
	ASSERT_EQ(out.payload.network.bytes, 256);
}

/* -------------------------------------------------------------------------
 * Runner
 * ----------------------------------------------------------------------- */

int main(void)
{
	printf("=== Owlbear BPF Loader Tests ===\n");

	RUN_TEST(bpf_convert_ptrace_event);
	RUN_TEST(bpf_convert_module_load_event);
	RUN_TEST(bpf_convert_vm_readv_event);
	RUN_TEST(bpf_convert_mprotect_event);
	RUN_TEST(bpf_convert_dev_mem_access_event);
	RUN_TEST(bpf_convert_null_input_fails);
	RUN_TEST(bpf_convert_null_output_fails);
	RUN_TEST(bpf_convert_too_small_fails);
	RUN_TEST(bpf_convert_unknown_type_uses_raw);
	RUN_TEST(bpf_convert_net_connect_event);
	RUN_TEST(bpf_convert_net_send_event);

	TEST_SUMMARY();
	return test_failures;
}
