// SPDX-License-Identifier: GPL-2.0-only
/*
 * owlbear_net.bpf.c - Network monitoring kprobes
 *
 * Observe-only kprobes on tcp_v4_connect and udp_sendmsg.
 * Filters by protected PID — only emits events for processes
 * in the protected_pids map. Does not block or modify traffic.
 *
 * Kprobes:
 *   tcp_v4_connect  - outbound TCP connection attempts
 *   udp_sendmsg     - outbound UDP sends
 */

#include "owlbear_common.bpf.h"

/* -------------------------------------------------------------------------
 * Kprobe: tcp_v4_connect
 *
 * Fires when a protected process initiates a TCP connection.
 * Reads the destination from uaddr (sockaddr_in passed by user).
 * ----------------------------------------------------------------------- */

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(owl_kprobe_tcp_connect, struct sock *sk,
	       struct sockaddr *uaddr, int addr_len)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	if (!is_protected(pid))
		return 0;

	struct sockaddr_in sin = {};

	if (bpf_probe_read_user(&sin, sizeof(sin), uaddr) < 0)
		return 0;

	if (sin.sin_family != 2)  /* AF_INET */
		return 0;

	/* Pack detail: dst_addr(4) + dst_port(2) + proto(2) + bytes(8) */
	struct owl_bpf_event *ev;

	ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev)
		return 0;

	ev->timestamp_ns = bpf_ktime_get_ns();
	ev->event_type = OWL_EVENT_NET_CONNECT;
	ev->severity = OWL_SEV_WARN;
	ev->pid = pid;
	ev->target_pid = pid;
	bpf_get_current_comm(ev->comm, sizeof(ev->comm));

	__builtin_memset(ev->detail, 0, sizeof(ev->detail));
	__builtin_memcpy(ev->detail + 0, &sin.sin_addr.s_addr, 4);
	__builtin_memcpy(ev->detail + 4, &sin.sin_port, 2);
	__u16 proto = 6;  /* IPPROTO_TCP */
	__builtin_memcpy(ev->detail + 6, &proto, 2);
	/* bytes = 0 for connect, already zeroed */

	bpf_ringbuf_submit(ev, 0);

	/* Increment event counter */
	__u32 zero = 0;
	__u64 *count = bpf_map_lookup_elem(&event_count, &zero);
	if (count)
		__sync_fetch_and_add(count, 1);

	return 0;
}

/* -------------------------------------------------------------------------
 * Kprobe: udp_sendmsg
 *
 * Fires when a protected process sends a UDP datagram.
 * Reads destination from msg->msg_name (sendto path) or falls
 * back to socket-level cached destination.
 * ----------------------------------------------------------------------- */

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(owl_kprobe_udp_sendmsg, struct sock *sk,
	       struct msghdr *msg, size_t len)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	if (!is_protected(pid))
		return 0;

	__u32 dst_addr = 0;
	__u16 dst_port = 0;

	/* Try msg->msg_name first (sendto path) */
	void *msg_name = NULL;
	int msg_namelen = 0;

	bpf_probe_read_kernel(&msg_name, sizeof(msg_name), &msg->msg_name);
	bpf_probe_read_kernel(&msg_namelen, sizeof(msg_namelen),
			      &msg->msg_namelen);

	if (msg_name && msg_namelen >= (int)sizeof(struct sockaddr_in)) {
		struct sockaddr_in sin = {};

		if (bpf_probe_read_kernel(&sin, sizeof(sin), msg_name) == 0 &&
		    sin.sin_family == 2) {
			dst_addr = sin.sin_addr.s_addr;
			dst_port = sin.sin_port;
		}
	}

	/* Fall back to socket cached destination */
	if (dst_addr == 0) {
		bpf_probe_read_kernel(&dst_addr, sizeof(dst_addr),
				      &sk->__sk_common.skc_daddr);
		bpf_probe_read_kernel(&dst_port, sizeof(dst_port),
				      &sk->__sk_common.skc_dport);
	}

	struct owl_bpf_event *ev;

	ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev)
		return 0;

	ev->timestamp_ns = bpf_ktime_get_ns();
	ev->event_type = OWL_EVENT_NET_SEND;
	ev->severity = OWL_SEV_WARN;
	ev->pid = pid;
	ev->target_pid = pid;
	bpf_get_current_comm(ev->comm, sizeof(ev->comm));

	__builtin_memset(ev->detail, 0, sizeof(ev->detail));
	__builtin_memcpy(ev->detail + 0, &dst_addr, 4);
	__builtin_memcpy(ev->detail + 4, &dst_port, 2);
	__u16 proto = 17;  /* IPPROTO_UDP */
	__builtin_memcpy(ev->detail + 6, &proto, 2);
	__u64 bytes_val = (__u64)len;
	__builtin_memcpy(ev->detail + 8, &bytes_val, 8);

	bpf_ringbuf_submit(ev, 0);

	__u32 zero = 0;
	__u64 *count = bpf_map_lookup_elem(&event_count, &zero);
	if (count)
		__sync_fetch_and_add(count, 1);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
