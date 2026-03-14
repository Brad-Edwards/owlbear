/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * owlbear_events.h - Shared event definitions for Owlbear anti-cheat
 *
 * This header is the contract between the kernel module, eBPF programs,
 * and the userspace daemon. All three components must agree on these
 * structures. Changes here require updating all consumers.
 *
 * Layout rules:
 *   - All fields are naturally aligned (no padding surprises across arches)
 *   - Fixed-size types only (__u32, __u64) for kernel/userspace compatibility
 *   - The union payload is fixed at 64 bytes to keep struct size predictable
 *   - Total struct size: 128 bytes (fits in two cache lines on ARM64)
 */

#ifndef OWLBEAR_EVENTS_H
#define OWLBEAR_EVENTS_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/ioctl.h>
#else
#include <stdint.h>
#include <linux/types.h>
#include <sys/ioctl.h>
#endif

/* -------------------------------------------------------------------------
 * Event Types
 * -------------------------------------------------------------------------
 * Grouped by subsystem for clarity. Ranges are reserved for future use:
 *   0x0000-0x00FF  Process lifecycle
 *   0x0100-0x01FF  Memory access violations
 *   0x0200-0x02FF  Integrity checks
 *   0x0300-0x03FF  ARM64 hardware checks
 *   0x0400-0x04FF  Signature / behavioral detection
 *   0x0500-0x05FF  System health / heartbeat
 * ----------------------------------------------------------------------- */

enum owlbear_event_type {
	/* Process lifecycle (0x00xx) */
	OWL_EVENT_PROCESS_CREATE        = 0x0001,
	OWL_EVENT_PROCESS_EXIT          = 0x0002,
	OWL_EVENT_PROCESS_EXEC          = 0x0003,

	/* Memory access violations (0x01xx) */
	OWL_EVENT_PTRACE_ATTEMPT        = 0x0100,
	OWL_EVENT_PROC_MEM_ACCESS       = 0x0101,
	OWL_EVENT_VM_READV_ATTEMPT      = 0x0102,
	OWL_EVENT_VM_WRITEV_ATTEMPT     = 0x0103,
	OWL_EVENT_EXEC_MMAP             = 0x0104,
	OWL_EVENT_MPROTECT_EXEC         = 0x0105,

	/* Integrity checks (0x02xx) */
	OWL_EVENT_MODULE_LOAD           = 0x0200,
	OWL_EVENT_MODULE_UNKNOWN        = 0x0201,
	OWL_EVENT_CODE_INTEGRITY_FAIL   = 0x0202,
	OWL_EVENT_LIB_UNEXPECTED        = 0x0203,

	/* ARM64 hardware checks (0x03xx) */
	OWL_EVENT_DEBUG_REG_ACTIVE      = 0x0300,
	OWL_EVENT_SYSREG_TAMPER         = 0x0301,
	OWL_EVENT_PAC_KEY_CHANGED       = 0x0302,
	OWL_EVENT_VBAR_MODIFIED         = 0x0303,
	OWL_EVENT_WXN_DISABLED          = 0x0304,

	/* Signature / behavioral detection (0x04xx) */
	OWL_EVENT_SIGNATURE_MATCH       = 0x0400,
	OWL_EVENT_BEHAVIORAL_THRESHOLD  = 0x0401,
	OWL_EVENT_CORRELATION_MATCH     = 0x0402,

	/* System health (0x05xx) */
	OWL_EVENT_HEARTBEAT_MISSED      = 0x0500,
	OWL_EVENT_EBPF_DETACHED         = 0x0501,
	OWL_EVENT_KMOD_UNLOADED         = 0x0502,
};

/* -------------------------------------------------------------------------
 * Severity Levels
 * ----------------------------------------------------------------------- */

enum owlbear_severity {
	OWL_SEV_INFO     = 0,   /* Informational — normal activity logged */
	OWL_SEV_WARN     = 1,   /* Suspicious — warrants investigation */
	OWL_SEV_CRITICAL = 2,   /* High-confidence cheat or tamper detected */
};

/* -------------------------------------------------------------------------
 * Event Source — which component generated this event
 * ----------------------------------------------------------------------- */

enum owlbear_source {
	OWL_SRC_KERNEL   = 0,   /* Kernel module (owlbear.ko) */
	OWL_SRC_EBPF     = 1,   /* eBPF program */
	OWL_SRC_DAEMON   = 2,   /* Userspace daemon */
};

/* -------------------------------------------------------------------------
 * Event-specific payload unions
 * ----------------------------------------------------------------------- */

/* Process event payload */
struct owl_payload_process {
	__u32 parent_pid;
	__u32 uid;
	char  filename[56];     /* Truncated path of the executable */
};

/* Memory access violation payload */
struct owl_payload_memory {
	__u32 caller_pid;
	__u32 access_type;      /* PTRACE, VM_READV, PROC_MEM, etc. */
	__u64 address;          /* Target address if available */
	__u64 size;             /* Size of attempted access */
	char  caller_comm[40];  /* Name of the accessing process */
};

/* Module/library event payload */
struct owl_payload_module {
	char  name[56];         /* Module or library name */
	__u64 base_addr;        /* Load address */
};

/* ARM64 hardware check payload */
struct owl_payload_arm64 {
	__u64 expected;         /* Expected register/hash value */
	__u64 actual;           /* Observed register/hash value */
	__u32 register_id;      /* Which register (encoded) */
	__u32 _reserved;
	char  description[40];  /* Human-readable description */
};

/* Signature match payload */
struct owl_payload_signature {
	char  rule_name[48];    /* Name of the matching signature rule */
	__u64 match_offset;     /* Offset within the target region */
	__u64 region_base;      /* Base address of scanned region */
};

/* -------------------------------------------------------------------------
 * Main Event Structure
 *
 * Fixed at 128 bytes. The union payload is 64 bytes. Every event carries
 * enough context to be self-describing without needing lookups.
 * ----------------------------------------------------------------------- */

struct owlbear_event {
	/* Header — 64 bytes */
	__u64 timestamp_ns;             /* Monotonic clock (CLOCK_MONOTONIC) */
	__u32 event_type;               /* enum owlbear_event_type */
	__u32 severity;                 /* enum owlbear_severity */
	__u32 source;                   /* enum owlbear_source */
	__u32 pid;                      /* PID of the process that caused this */
	__u32 target_pid;               /* PID of the protected process */
	__u32 sequence;                 /* Per-source monotonic sequence number */
	char  comm[16];                 /* Process name (comm) of causal process */
	__u64 session_id;               /* Session identifier (set by daemon) */
	__u64 _reserved;                /* Future use — must be zero */

	/* Payload — 64 bytes */
	union {
		struct owl_payload_process   process;
		struct owl_payload_memory    memory;
		struct owl_payload_module    module;
		struct owl_payload_arm64     arm64;
		struct owl_payload_signature signature;
		__u8 raw[64];               /* For direct byte access */
	} payload;
};

/* Compile-time size verification */
#ifdef __KERNEL__
#include <linux/build_bug.h>
#define OWL_EVENT_STATIC_ASSERT() \
	BUILD_BUG_ON(sizeof(struct owlbear_event) != 128)
#else
_Static_assert(sizeof(struct owlbear_event) == 128,
	       "owlbear_event must be exactly 128 bytes");
#endif

/* -------------------------------------------------------------------------
 * IOCTL Interface — kernel module <-> daemon
 * ----------------------------------------------------------------------- */

#define OWL_IOC_MAGIC 0xB4  /* 'Owl' -> 0xB4 arbitrary but unique */

/* Set the PID to protect. Arg: __u32 pid */
#define OWL_IOC_SET_TARGET      _IOW(OWL_IOC_MAGIC, 0x01, __u32)

/* Clear protection (stop protecting any PID). No arg. */
#define OWL_IOC_CLEAR_TARGET    _IO(OWL_IOC_MAGIC, 0x02)

/* Get current status. Arg: struct owl_status (output) */
#define OWL_IOC_GET_STATUS      _IOR(OWL_IOC_MAGIC, 0x03, struct owl_status)

/* Set enforcement mode. Arg: __u32 (0=observe, 1=block) */
#define OWL_IOC_SET_MODE        _IOW(OWL_IOC_MAGIC, 0x04, __u32)

/* Status structure returned by OWL_IOC_GET_STATUS */
struct owl_status {
	__u32 target_pid;       /* Currently protected PID (0 = none) */
	__u32 enforce_mode;     /* 0 = observe, 1 = block */
	__u32 events_generated; /* Total events since module load */
	__u32 events_dropped;   /* Events dropped due to full buffer */
	__u32 kmod_version;     /* Kernel module version (packed) */
	__u32 _reserved[3];     /* Future use */
};

/* -------------------------------------------------------------------------
 * Heartbeat Protocol — game <-> daemon <-> platform
 * ----------------------------------------------------------------------- */

/* Game -> Daemon (local Unix socket, every 2 seconds) */
struct owl_heartbeat_game {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 frame_count;      /* Game's frame counter — detects freeze/tamper */
	__u32 state_hash;       /* CRC32 of critical game state */
	__u32 _reserved;
};

/* Daemon -> Platform (HTTPS, every 15 seconds) */
struct owl_heartbeat_platform {
	__u64 timestamp_ns;
	__u32 game_pid;
	__u32 events_since_last; /* Detection events since last heartbeat */
	__u32 severity_max;      /* Highest severity event since last heartbeat */
	__u32 ebpf_attached;     /* Boolean: are eBPF programs still loaded? */
	__u32 kmod_loaded;       /* Boolean: is kernel module responsive? */
	__u32 _reserved;
	char  hostname[64];
	char  kernel_version[64];
};

/* Platform -> Daemon (HTTPS response) */
enum owl_platform_action {
	OWL_ACTION_CONTINUE             = 0,
	OWL_ACTION_INCREASE_MONITORING  = 1,
	OWL_ACTION_KILL_GAME            = 2,
};

struct owl_platform_response {
	__u32 action;           /* enum owl_platform_action */
	__u32 sig_version;      /* Signature DB version — update if newer */
	__u64 _reserved;
};

/* -------------------------------------------------------------------------
 * Device and path constants
 * ----------------------------------------------------------------------- */

#define OWL_DEVICE_NAME         "owlbear"
#define OWL_DEVICE_PATH         "/dev/owlbear"
#define OWL_HEARTBEAT_SOCK_PATH "/run/owlbear/heartbeat.sock"
#define OWL_EVENT_RING_SIZE     4096    /* Max events in kernel ring buffer */
#define OWL_KMOD_VERSION        0x000100 /* 0.1.0 */

#endif /* OWLBEAR_EVENTS_H */
