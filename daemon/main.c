// SPDX-License-Identifier: GPL-2.0-only
/*
 * owlbeard - Owlbear anti-cheat userspace daemon
 *
 * Opens /dev/owlbear, sets the target PID, loads eBPF programs,
 * configures the event pipeline (policy + scanner + integrity),
 * and multiplexes kernel chardev + BPF ringbuf events via epoll.
 *
 * Usage:
 *   owlbeard --target <pid> [--enforce] [--log <path>] [--sigs <path>]
 *            [--verbose | --quiet]
 *   owlbeard --help
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

#include "owlbear_events.h"
#include "bpf_loader.h"
#include "event_pipeline.h"
#include "integrity.h"
#include "net_allowlist.h"
#include "process_tree.h"
#include "policy.h"
#include "scanner.h"
#include "self_protect.h"
#include "debugger_detect.h"
#include "clock_validator.h"
#include "vdso_integrity.h"
#include "sig_loader.h"
#include "log.h"

/* -------------------------------------------------------------------------
 * Configuration
 * ----------------------------------------------------------------------- */

#define OWL_DEFAULT_SIGS_PATH   "../signatures/default.sigs"
#define OWL_PERIODIC_INTERVAL_S 30
#define OWL_WATCHDOG_INTERVAL_S 5
#define OWL_EPOLL_TIMEOUT_MS    1000  /* 1 second for periodic timer checks */

enum owl_log_level g_owl_log_level = OWL_LOG_INFO;

struct daemon_config {
	pid_t       target_pid;
	bool        enforce;
	const char *log_path;
	const char *device_path;
	const char *sigs_path;
};

/* -------------------------------------------------------------------------
 * Signal handling - clean shutdown
 * ----------------------------------------------------------------------- */

static volatile sig_atomic_t g_running = 1;

static void signal_handler(int sig)
{
	(void)sig;
	g_running = 0;
}

static int install_signal_handlers(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGINT, &sa, NULL) < 0) {
		OWL_ERR("sigaction(SIGINT): %s", strerror(errno));
		return -1;
	}
	if (sigaction(SIGTERM, &sa, NULL) < 0) {
		OWL_ERR("sigaction(SIGTERM): %s", strerror(errno));
		return -1;
	}

	return 0;
}

/* -------------------------------------------------------------------------
 * Event formatting
 * ----------------------------------------------------------------------- */

static const char *event_type_str(uint32_t type)
{
	switch (type) {
	case OWL_EVENT_PROCESS_CREATE:       return "PROCESS_CREATE";
	case OWL_EVENT_PROCESS_EXIT:         return "PROCESS_EXIT";
	case OWL_EVENT_PROCESS_EXEC:         return "PROCESS_EXEC";
	case OWL_EVENT_PTRACE_ATTEMPT:       return "PTRACE_ATTEMPT";
	case OWL_EVENT_PROC_MEM_ACCESS:      return "PROC_MEM_ACCESS";
	case OWL_EVENT_VM_READV_ATTEMPT:     return "VM_READV_ATTEMPT";
	case OWL_EVENT_VM_WRITEV_ATTEMPT:    return "VM_WRITEV_ATTEMPT";
	case OWL_EVENT_EXEC_MMAP:            return "EXEC_MMAP";
	case OWL_EVENT_MPROTECT_EXEC:        return "MPROTECT_EXEC";
	case OWL_EVENT_DEV_MEM_ACCESS:       return "DEV_MEM_ACCESS";
	case OWL_EVENT_MODULE_LOAD:          return "MODULE_LOAD";
	case OWL_EVENT_MODULE_UNKNOWN:       return "MODULE_UNKNOWN";
	case OWL_EVENT_CODE_INTEGRITY_FAIL:  return "CODE_INTEGRITY_FAIL";
	case OWL_EVENT_LIB_UNEXPECTED:       return "LIB_UNEXPECTED";
	case OWL_EVENT_DEBUG_REG_ACTIVE:     return "DEBUG_REG_ACTIVE";
	case OWL_EVENT_SYSREG_TAMPER:        return "SYSREG_TAMPER";
	case OWL_EVENT_PAC_KEY_CHANGED:      return "PAC_KEY_CHANGED";
	case OWL_EVENT_VBAR_MODIFIED:        return "VBAR_MODIFIED";
	case OWL_EVENT_WXN_DISABLED:         return "WXN_DISABLED";
	case OWL_EVENT_SIGNATURE_MATCH:      return "SIGNATURE_MATCH";
	case OWL_EVENT_BEHAVIORAL_THRESHOLD: return "BEHAVIORAL_THRESHOLD";
	case OWL_EVENT_CORRELATION_MATCH:    return "CORRELATION_MATCH";
	case OWL_EVENT_HEARTBEAT_MISSED:     return "HEARTBEAT_MISSED";
	case OWL_EVENT_EBPF_DETACHED:        return "EBPF_DETACHED";
	case OWL_EVENT_KMOD_UNLOADED:        return "KMOD_UNLOADED";
	case OWL_EVENT_NET_CONNECT:          return "NET_CONNECT";
	case OWL_EVENT_NET_SEND:             return "NET_SEND";
	case OWL_EVENT_CLOCK_DRIFT:          return "CLOCK_DRIFT";
	case OWL_EVENT_VDSO_TAMPER:          return "VDSO_TAMPER";
	default:                             return "UNKNOWN";
	}
}

static const char *severity_str(uint32_t severity)
{
	switch (severity) {
	case OWL_SEV_INFO:     return "INFO";
	case OWL_SEV_WARN:     return "WARN";
	case OWL_SEV_CRITICAL: return "CRIT";
	default:               return "????";
	}
}

static const char *source_str(uint32_t source)
{
	switch (source) {
	case OWL_SRC_KERNEL: return "KMOD";
	case OWL_SRC_EBPF:   return "EBPF";
	case OWL_SRC_DAEMON: return "DAEMON";
	default:             return "????";
	}
}

static void format_timestamp(uint64_t ns, char *buf, size_t len)
{
	time_t secs = (time_t)(ns / 1000000000ULL);
	unsigned int ms = (unsigned int)((ns / 1000000ULL) % 1000);
	struct tm tm;

	localtime_r(&secs, &tm);
	snprintf(buf, len, "%04d-%02d-%02d %02d:%02d:%02d.%03u",
		 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
		 tm.tm_hour, tm.tm_min, tm.tm_sec, ms);
}

static void print_event(const struct owlbear_event *ev, FILE *out)
{
	char ts[80];

	format_timestamp(ev->timestamp_ns, ts, sizeof(ts));

	fprintf(out, "[%s] [%s] [%s] seq=%u pid=%u target=%u comm=%s type=%s",
		ts,
		severity_str(ev->severity),
		source_str(ev->source),
		ev->sequence,
		ev->pid,
		ev->target_pid,
		ev->comm,
		event_type_str(ev->event_type));

	/* Print event-specific payload details */
	switch (ev->event_type) {
	case OWL_EVENT_PROCESS_CREATE:
	case OWL_EVENT_PROCESS_EXEC:
		fprintf(out, " parent=%u uid=%u file=%s",
			ev->payload.process.parent_pid,
			ev->payload.process.uid,
			ev->payload.process.filename);
		break;

	case OWL_EVENT_PTRACE_ATTEMPT:
	case OWL_EVENT_PROC_MEM_ACCESS:
	case OWL_EVENT_VM_READV_ATTEMPT:
	case OWL_EVENT_VM_WRITEV_ATTEMPT:
	case OWL_EVENT_MPROTECT_EXEC:
	case OWL_EVENT_DEV_MEM_ACCESS:
		fprintf(out, " caller_pid=%u caller=%s",
			ev->payload.memory.caller_pid,
			ev->payload.memory.caller_comm);
		break;

	case OWL_EVENT_MODULE_LOAD:
	case OWL_EVENT_MODULE_UNKNOWN:
	case OWL_EVENT_LIB_UNEXPECTED:
		fprintf(out, " name=%s base=0x%llx",
			ev->payload.module.name,
			(unsigned long long)ev->payload.module.base_addr);
		break;

	case OWL_EVENT_DEBUG_REG_ACTIVE:
	case OWL_EVENT_SYSREG_TAMPER:
	case OWL_EVENT_PAC_KEY_CHANGED:
	case OWL_EVENT_VBAR_MODIFIED:
	case OWL_EVENT_WXN_DISABLED:
	case OWL_EVENT_CLOCK_DRIFT:
	case OWL_EVENT_VDSO_TAMPER:
		fprintf(out, " reg=%u expected=0x%llx actual=0x%llx desc=%s",
			ev->payload.arm64.register_id,
			(unsigned long long)ev->payload.arm64.expected,
			(unsigned long long)ev->payload.arm64.actual,
			ev->payload.arm64.description);
		break;

	case OWL_EVENT_SIGNATURE_MATCH:
		fprintf(out, " rule=%s offset=0x%llx base=0x%llx",
			ev->payload.signature.rule_name,
			(unsigned long long)ev->payload.signature.match_offset,
			(unsigned long long)ev->payload.signature.region_base);
		break;

	case OWL_EVENT_NET_CONNECT:
	case OWL_EVENT_NET_SEND: {
		uint32_t a = ev->payload.network.dst_addr;
		fprintf(out, " dst=%u.%u.%u.%u:%u proto=%u bytes=%llu proc=%s",
			a & 0xFF, (a >> 8) & 0xFF,
			(a >> 16) & 0xFF, (a >> 24) & 0xFF,
			ntohs(ev->payload.network.dst_port),
			ev->payload.network.protocol,
			(unsigned long long)ev->payload.network.bytes,
			ev->payload.network.comm);
		break;
	}

	default:
		break;
	}

	fprintf(out, "\n");
	fflush(out);
}

/* -------------------------------------------------------------------------
 * Device interaction
 * ----------------------------------------------------------------------- */

static int open_device(const char *path)
{
	int fd = open(path, O_RDONLY);

	if (fd < 0) {
		OWL_ERR("failed to open %s: %s", path, strerror(errno));
		if (errno == ENOENT)
			OWL_ERR("  Is the owlbear kernel module loaded?");
		else if (errno == EACCES)
			OWL_ERR("  Try running as root.");
	}

	return fd;
}

static int set_target_pid(int fd, pid_t pid)
{
	__u32 p = (__u32)pid;

	if (ioctl(fd, OWL_IOC_SET_TARGET, &p) < 0) {
		OWL_ERR("failed to set target PID %d: %s", pid, strerror(errno));
		return -1;
	}

	OWL_INFO("protecting PID %d", pid);
	return 0;
}

static int set_enforce_mode(int fd, bool enforce)
{
	__u32 mode = enforce ? 1 : 0;

	if (ioctl(fd, OWL_IOC_SET_MODE, &mode) < 0) {
		OWL_ERR("failed to set enforce mode: %s", strerror(errno));
		return -1;
	}

	OWL_INFO("enforcement mode: %s", enforce ? "BLOCK" : "OBSERVE");
	return 0;
}

static int print_status(int fd)
{
	struct owl_status status;

	if (ioctl(fd, OWL_IOC_GET_STATUS, &status) < 0) {
		OWL_ERR("failed to get status: %s", strerror(errno));
		return -1;
	}

	OWL_INFO("status:");
	OWL_INFO("  target_pid:    %u", status.target_pid);
	OWL_INFO("  enforce_mode:  %s", status.enforce_mode ? "block" : "observe");
	OWL_INFO("  events_total:  %u", status.events_generated);
	OWL_INFO("  events_dropped: %u", status.events_dropped);
	OWL_INFO("  kmod_version:  %u.%u.%u",
		 (status.kmod_version >> 16) & 0xFF,
		 (status.kmod_version >> 8) & 0xFF,
		 status.kmod_version & 0xFF);

	return 0;
}

/* -------------------------------------------------------------------------
 * BPF event callback — invoked from ring buffer poll
 * ----------------------------------------------------------------------- */

struct bpf_cb_ctx {
	struct owl_pipeline *pipeline;
	FILE               *log_file;
};

static void bpf_event_callback(const struct owlbear_event *ev, void *ctx)
{
	struct bpf_cb_ctx *cb = ctx;

	/* Print the raw event */
	print_event(ev, stdout);
	if (cb->log_file)
		print_event(ev, cb->log_file);

	/* Run through pipeline */
	owl_pipeline_process(cb->pipeline, ev);
}

/* -------------------------------------------------------------------------
 * Event loop — epoll multiplexer
 * ----------------------------------------------------------------------- */

static int event_loop(int dev_fd, struct owl_bpf_ctx *bpf,
		      struct owl_pipeline *pipeline,
		      struct owl_integrity *integrity,
		      struct owl_self_protect *selfprot,
		      struct owl_debugger_detect *dbg_detect,
		      struct owl_clock_validator *clock_val,
		      struct owl_vdso_integrity *vdso_integ,
		      FILE *log_file)
{
	int epfd;
	struct epoll_event ev;
	struct epoll_event events[4];
	struct owlbear_event kmod_event;
	time_t last_periodic = 0;
	time_t last_watchdog = 0;

	epfd = epoll_create1(EPOLL_CLOEXEC);
	if (epfd < 0) {
		OWL_ERR("epoll_create1: %s", strerror(errno));
		return -1;
	}

	/* Add kernel chardev fd — include HUP/ERR for module unload detection */
	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN | EPOLLHUP | EPOLLERR;
	ev.data.fd = dev_fd;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, dev_fd, &ev) < 0) {
		OWL_ERR("epoll_ctl(dev_fd): %s", strerror(errno));
		close(epfd);
		return -1;
	}

	/* Add BPF ring buffer fd if available */
	int bpf_fd = owl_bpf_ringbuf_fd(bpf);
	if (bpf_fd >= 0) {
		memset(&ev, 0, sizeof(ev));
		ev.events = EPOLLIN;
		ev.data.fd = bpf_fd;
		if (epoll_ctl(epfd, EPOLL_CTL_ADD, bpf_fd, &ev) < 0) {
			OWL_WARN("epoll_ctl(bpf_fd) failed: %s", strerror(errno));
			/* Non-fatal: we can still poll BPF manually */
		}
	}

	OWL_INFO("listening for events (epoll, fds: dev=%d bpf=%d)...",
		 dev_fd, bpf_fd);

	while (g_running) {
		int nfds = epoll_wait(epfd, events, 4, OWL_EPOLL_TIMEOUT_MS);

		if (nfds < 0) {
			if (errno == EINTR)
				continue;
			OWL_ERR("epoll_wait: %s", strerror(errno));
			close(epfd);
			return -1;
		}

		/* Process epoll events */
		for (int i = 0; i < nfds; i++) {
			if (events[i].data.fd == dev_fd &&
			    (events[i].events & (EPOLLHUP | EPOLLERR))) {
				/* Device gone — module unloaded */
				OWL_WARN("device closed (module unloaded)");
				epoll_ctl(epfd, EPOLL_CTL_DEL, dev_fd, NULL);
				dev_fd = -1;
				continue;
			}

			if (events[i].data.fd == dev_fd) {
				/* Kernel chardev event */
				ssize_t n = read(dev_fd, &kmod_event,
						 sizeof(kmod_event));

				if (n < 0) {
					if (errno == EINTR)
						continue;
					if (errno == EAGAIN)
						continue;
					OWL_ERR("device read error: %s (module unloaded?)",
					strerror(errno));
					epoll_ctl(epfd, EPOLL_CTL_DEL, dev_fd, NULL);
					dev_fd = -1;
					continue;
				}

				if (n == 0) {
					OWL_WARN("device closed (module unloaded)");
					epoll_ctl(epfd, EPOLL_CTL_DEL, dev_fd, NULL);
					dev_fd = -1;
					continue;
				}

				if ((size_t)n == sizeof(kmod_event)) {
					print_event(&kmod_event, stdout);
					if (log_file)
						print_event(&kmod_event, log_file);
					owl_pipeline_process(pipeline,
							     &kmod_event);
				}

			} else if (events[i].data.fd == bpf_fd) {
				/* BPF ring buffer event */
				owl_bpf_poll(bpf, 0);
			}
		}

		/* Periodic tasks */
		time_t now = time(NULL);

		/* Signature scan + integrity check every 30s */
		if (now - last_periodic >= OWL_PERIODIC_INTERVAL_S) {
			last_periodic = now;

			/* Signature scan */
			int matches = owl_pipeline_scan(pipeline);
			if (matches > 0)
				OWL_INFO("periodic scan: %d signature matches",
					 matches);

			/* Integrity check */
			if (integrity && integrity->baseline_set) {
				int ic = owl_integrity_check(integrity);
				if (ic == 1) {
					OWL_WARN("[ALERT] code integrity violation!");

					struct owlbear_event ie;
					struct timespec ts;
					memset(&ie, 0, sizeof(ie));
					clock_gettime(CLOCK_MONOTONIC, &ts);
					ie.timestamp_ns = (uint64_t)ts.tv_sec * 1000000000ULL +
							  (uint64_t)ts.tv_nsec;
					ie.event_type = OWL_EVENT_CODE_INTEGRITY_FAIL;
					ie.severity = OWL_SEV_CRITICAL;
					ie.source = OWL_SRC_DAEMON;
					ie.pid = (uint32_t)pipeline->target_pid;
					ie.target_pid = (uint32_t)pipeline->target_pid;
					owl_pipeline_process(pipeline, &ie);
				}
			}

			/* vDSO integrity check (30s periodic) */
			if (vdso_integ && vdso_integ->baseline_set) {
				int vc = owl_vdso_integrity_check(vdso_integ);
				if (vc == 1) {
					OWL_WARN("[ALERT] vDSO tamper detected!");

					struct owlbear_event ve;
					struct timespec ts;
					memset(&ve, 0, sizeof(ve));
					clock_gettime(CLOCK_MONOTONIC, &ts);
					ve.timestamp_ns = (uint64_t)ts.tv_sec * 1000000000ULL +
							  (uint64_t)ts.tv_nsec;
					ve.event_type = OWL_EVENT_VDSO_TAMPER;
					ve.severity = OWL_SEV_CRITICAL;
					ve.source = OWL_SRC_DAEMON;
					ve.target_pid = (uint32_t)pipeline->target_pid;
					snprintf(ve.payload.arm64.description,
						 sizeof(ve.payload.arm64.description),
						 "vDSO HMAC mismatch");

					print_event(&ve, stdout);
					if (log_file)
						print_event(&ve, log_file);
					owl_pipeline_process(pipeline, &ve);
				}
			}
		}

		/* Self-protection watchdog every 5s */
		if (selfprot && now - last_watchdog >= OWL_WATCHDOG_INTERVAL_S) {
			last_watchdog = now;

			int sp_result = owl_selfprotect_watchdog(selfprot);

			if (sp_result & 0x01) {
				/* Module unloaded */
				struct owlbear_event me;
				struct timespec ts;
				memset(&me, 0, sizeof(me));
				clock_gettime(CLOCK_MONOTONIC, &ts);
				me.timestamp_ns = (uint64_t)ts.tv_sec * 1000000000ULL +
						  (uint64_t)ts.tv_nsec;
				me.event_type = OWL_EVENT_MODULE_UNKNOWN;
				me.severity = OWL_SEV_CRITICAL;
				me.source = OWL_SRC_DAEMON;
				me.target_pid = (uint32_t)pipeline->target_pid;
				strncpy(me.payload.module.name, "owlbear",
					sizeof(me.payload.module.name) - 1);

				print_event(&me, stdout);
				if (log_file)
					print_event(&me, log_file);
			}

			if (sp_result & 0x04) {
				/* BPF detached */
				struct owlbear_event be;
				struct timespec ts;
				memset(&be, 0, sizeof(be));
				clock_gettime(CLOCK_MONOTONIC, &ts);
				be.timestamp_ns = (uint64_t)ts.tv_sec * 1000000000ULL +
						  (uint64_t)ts.tv_nsec;
				be.event_type = OWL_EVENT_EBPF_DETACHED;
				be.severity = OWL_SEV_CRITICAL;
				be.source = OWL_SRC_DAEMON;
				be.target_pid = (uint32_t)pipeline->target_pid;

				print_event(&be, stdout);
				if (log_file)
					print_event(&be, log_file);
			}

			/* TracerPid debugger detection */
			if (dbg_detect) {
				int dbg_result = owl_debugger_detect_check(dbg_detect);
				if (dbg_result & 0x01) {
					OWL_WARN("[ALERT] debugger attached (TracerPid=%d)!",
						 dbg_detect->last_tracer);

					struct owlbear_event de;
					struct timespec ts;
					memset(&de, 0, sizeof(de));
					clock_gettime(CLOCK_MONOTONIC, &ts);
					de.timestamp_ns = (uint64_t)ts.tv_sec * 1000000000ULL +
							  (uint64_t)ts.tv_nsec;
					de.event_type = OWL_EVENT_PTRACE_ATTEMPT;
					de.severity = OWL_SEV_CRITICAL;
					de.source = OWL_SRC_DAEMON;
					de.pid = (uint32_t)dbg_detect->last_tracer;
					de.target_pid = (uint32_t)pipeline->target_pid;
					de.payload.memory.caller_pid = (uint32_t)dbg_detect->last_tracer;

					print_event(&de, stdout);
					if (log_file)
						print_event(&de, log_file);
					owl_pipeline_process(pipeline, &de);
				}
			}

			/* Clock drift detection (5s watchdog) */
			if (clock_val) {
				int clk_result = owl_clock_validator_check(clock_val);
				if (clk_result & 0x01) {
					OWL_WARN("[ALERT] clock drift detected!");

					struct owlbear_event ce;
					struct timespec ts;
					memset(&ce, 0, sizeof(ce));
					clock_gettime(CLOCK_MONOTONIC, &ts);
					ce.timestamp_ns = (uint64_t)ts.tv_sec * 1000000000ULL +
							  (uint64_t)ts.tv_nsec;
					ce.event_type = OWL_EVENT_CLOCK_DRIFT;
					ce.severity = OWL_SEV_CRITICAL;
					ce.source = OWL_SRC_DAEMON;
					ce.target_pid = (uint32_t)pipeline->target_pid;
					snprintf(ce.payload.arm64.description,
						 sizeof(ce.payload.arm64.description),
						 "MONO vs RAW drift >50ms");

					print_event(&ce, stdout);
					if (log_file)
						print_event(&ce, log_file);
					owl_pipeline_process(pipeline, &ce);
				}
			}
		}
	}

	close(epfd);
	return 0;
}

/* -------------------------------------------------------------------------
 * CLI parsing
 * ----------------------------------------------------------------------- */

static void print_usage(const char *progname)
{
	fprintf(stderr,
		"Usage: %s --target <pid> [options]\n"
		"\n"
		"Options:\n"
		"  -t, --target <pid>   PID of the process to protect (required)\n"
		"  -e, --enforce        Enable enforcement mode (block, not just log)\n"
		"  -l, --log <path>     Write events to log file\n"
		"  -d, --device <path>  Device path (default: /dev/owlbear)\n"
		"  -s, --sigs <path>    Signature file (default: %s)\n"
		"  -v, --verbose        Verbose output (show debug messages)\n"
		"  -q, --quiet          Quiet output (errors and warnings only)\n"
		"  -h, --help           Show this help\n"
		"\n"
		"Example:\n"
		"  %s --target $(pidof owlbear-game) --enforce --log /var/log/owlbear.log\n",
		progname, OWL_DEFAULT_SIGS_PATH, progname);
}

static int parse_args(int argc, char *argv[], struct daemon_config *cfg)
{
	static const struct option long_opts[] = {
		{ "target",  required_argument, NULL, 't' },
		{ "enforce", no_argument,       NULL, 'e' },
		{ "log",     required_argument, NULL, 'l' },
		{ "device",  required_argument, NULL, 'd' },
		{ "sigs",    required_argument, NULL, 's' },
		{ "verbose", no_argument,       NULL, 'v' },
		{ "quiet",   no_argument,       NULL, 'q' },
		{ "help",    no_argument,       NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};
	int opt;
	long pid_val;
	char *endptr;

	/* Defaults */
	cfg->target_pid = 0;
	cfg->enforce = false;
	cfg->log_path = NULL;
	cfg->device_path = OWL_DEVICE_PATH;
	cfg->sigs_path = OWL_DEFAULT_SIGS_PATH;

	while ((opt = getopt_long(argc, argv, "t:el:d:s:vqh", long_opts, NULL)) != -1) {
		switch (opt) {
		case 't':
			errno = 0;
			pid_val = strtol(optarg, &endptr, 10);
			if (errno != 0 || *endptr != '\0' || pid_val <= 0) {
				OWL_ERR("invalid PID: %s", optarg);
				return -1;
			}
			cfg->target_pid = (pid_t)pid_val;
			break;
		case 'e':
			cfg->enforce = true;
			break;
		case 'l':
			cfg->log_path = optarg;
			break;
		case 'd':
			cfg->device_path = optarg;
			break;
		case 's':
			cfg->sigs_path = optarg;
			break;
		case 'v':
			g_owl_log_level = OWL_LOG_DBG;
			break;
		case 'q':
			g_owl_log_level = OWL_LOG_WARN;
			break;
		case 'h':
			print_usage(argv[0]);
			exit(0);
		default:
			print_usage(argv[0]);
			return -1;
		}
	}

	if (cfg->target_pid == 0) {
		OWL_ERR("--target <pid> is required");
		print_usage(argv[0]);
		return -1;
	}

	return 0;
}

/* -------------------------------------------------------------------------
 * Default policy rules
 * ----------------------------------------------------------------------- */

static void setup_default_policy(struct owl_policy *policy, bool enforce)
{
	owl_policy_init(policy);

	if (enforce) {
		/* In enforce mode: block all memory access attempts */
		owl_policy_add_rule(policy, OWL_EVENT_PTRACE_ATTEMPT,
				    OWL_SEV_INFO, OWL_ACT_BLOCK);
		owl_policy_add_rule(policy, OWL_EVENT_PROC_MEM_ACCESS,
				    OWL_SEV_INFO, OWL_ACT_BLOCK);
		owl_policy_add_rule(policy, OWL_EVENT_VM_READV_ATTEMPT,
				    OWL_SEV_INFO, OWL_ACT_BLOCK);
		owl_policy_add_rule(policy, OWL_EVENT_VM_WRITEV_ATTEMPT,
				    OWL_SEV_INFO, OWL_ACT_BLOCK);

		/* Kill on critical integrity violations */
		owl_policy_add_rule(policy, OWL_EVENT_CODE_INTEGRITY_FAIL,
				    OWL_SEV_CRITICAL, OWL_ACT_KILL);

		/* Kill on critical speed hack detections */
		owl_policy_add_rule(policy, OWL_EVENT_CLOCK_DRIFT,
				    OWL_SEV_CRITICAL, OWL_ACT_KILL);
		owl_policy_add_rule(policy, OWL_EVENT_VDSO_TAMPER,
				    OWL_SEV_CRITICAL, OWL_ACT_KILL);
	}

	/* Always log signature matches */
	owl_policy_add_rule(policy, OWL_EVENT_SIGNATURE_MATCH,
			    OWL_SEV_INFO, OWL_ACT_LOG);

	/* Log module events */
	owl_policy_add_rule(policy, OWL_EVENT_MODULE_LOAD,
			    OWL_SEV_INFO, OWL_ACT_LOG);
	owl_policy_add_rule(policy, OWL_EVENT_MODULE_UNKNOWN,
			    OWL_SEV_INFO, OWL_ACT_LOG);

	/* Log network events */
	owl_policy_add_rule(policy, OWL_EVENT_NET_CONNECT,
			    OWL_SEV_INFO, OWL_ACT_LOG);
	owl_policy_add_rule(policy, OWL_EVENT_NET_SEND,
			    OWL_SEV_INFO, OWL_ACT_LOG);

	/* Log speed hack / time integrity events */
	owl_policy_add_rule(policy, OWL_EVENT_CLOCK_DRIFT,
			    OWL_SEV_INFO, OWL_ACT_LOG);
	owl_policy_add_rule(policy, OWL_EVENT_VDSO_TAMPER,
			    OWL_SEV_INFO, OWL_ACT_LOG);

	/* Log ARM64 hardware anomalies */
	owl_policy_add_rule(policy, 0, OWL_SEV_WARN, OWL_ACT_LOG);
}

/* -------------------------------------------------------------------------
 * Main
 * ----------------------------------------------------------------------- */

int main(int argc, char *argv[])
{
	struct daemon_config cfg;
	FILE *log_file = NULL;
	int dev_fd = -1;
	int ret = EXIT_FAILURE;

	struct owl_policy policy;
	struct owl_sig_db sig_db;
	struct owl_ptree ptree;
	struct owl_net_allowlist net_al;
	struct owl_pipeline pipeline;
	struct owl_integrity integrity;
	struct owl_self_protect selfprot;
	struct owl_debugger_detect dbg_detect;
	struct owl_clock_validator clock_val;
	struct owl_vdso_integrity vdso_integ;
	struct owl_bpf_ctx *bpf = NULL;

	if (parse_args(argc, argv, &cfg) < 0)
		return EXIT_FAILURE;

	if (install_signal_handlers() < 0)
		return EXIT_FAILURE;

	/* Open log file if requested */
	if (cfg.log_path) {
		log_file = fopen(cfg.log_path, "a");
		if (!log_file) {
			OWL_ERR("failed to open log %s: %s",
			cfg.log_path, strerror(errno));
			return EXIT_FAILURE;
		}
		setlinebuf(log_file);
		OWL_INFO("logging to %s", cfg.log_path);
	}

	/* Setup policy engine */
	setup_default_policy(&policy, cfg.enforce);

	/* Load signatures */
	owl_sig_db_init(&sig_db);
	int nsigs = owl_sig_load_file(&sig_db, cfg.sigs_path);
	if (nsigs >= 0) {
		OWL_INFO("loaded %d signatures from %s", nsigs, cfg.sigs_path);
	} else {
		OWL_ERR("failed to load signatures from %s", cfg.sigs_path);
		/* Non-fatal: scanner will just not match anything */
	}

	/* Initialize process tree */
	owl_ptree_init(&ptree);

	/* Initialize network allowlist */
	owl_net_allowlist_init(&net_al);
	/* Default server IPs — add known game servers here */
	owl_net_allowlist_add(&net_al, inet_addr("127.0.0.1"));

	/* Initialize event pipeline */
	owl_pipeline_init(&pipeline, &policy, &sig_db, &ptree, &net_al,
			  cfg.target_pid, cfg.enforce, log_file);

	/* Open the kernel device */
	dev_fd = open_device(cfg.device_path);
	if (dev_fd < 0)
		goto cleanup;

	/* Configure the kernel module */
	if (set_target_pid(dev_fd, cfg.target_pid) < 0)
		goto cleanup;

	if (set_enforce_mode(dev_fd, cfg.enforce) < 0)
		goto cleanup;

	/* Print initial status */
	print_status(dev_fd);

	/* Initialize BPF programs */
	struct bpf_cb_ctx bpf_cb = {
		.pipeline = &pipeline,
		.log_file = log_file,
	};
	bpf = owl_bpf_init(bpf_event_callback, &bpf_cb);
	if (bpf) {
		/* Populate BPF maps */
		if (owl_bpf_protect_pid(bpf, (uint32_t)cfg.target_pid) < 0)
			OWL_ERR("failed to set protected PID in BPF map");

		/* Whitelist the daemon itself */
		if (owl_bpf_allow_pid(bpf, (uint32_t)getpid()) < 0)
			OWL_ERR("failed to whitelist daemon in BPF map");

		/* Whitelist the game process */
		if (owl_bpf_allow_pid(bpf, (uint32_t)cfg.target_pid) < 0)
			OWL_ERR("failed to whitelist game in BPF map");

		OWL_INFO("BPF: lsm=%s trace=%s kprobe=%s net=%s",
			 owl_bpf_has_lsm(bpf) ? "yes" : "no",
			 owl_bpf_has_trace(bpf) ? "yes" : "no",
			 owl_bpf_has_kprobe(bpf) ? "yes" : "no",
			 owl_bpf_has_net(bpf) ? "yes" : "no");
	}

	/* Initialize code integrity baseline */
	owl_integrity_init_ctx(&integrity);
	if (owl_integrity_baseline(&integrity, cfg.target_pid) < 0) {
		OWL_WARN("integrity baseline failed (non-fatal)");
	}

	/* Initialize self-protection */
	owl_selfprotect_init(&selfprot, dev_fd, owl_bpf_ringbuf_fd(bpf));

	/* Initialize debugger detection */
	owl_debugger_detect_init(&dbg_detect, cfg.target_pid);

	/* Initialize clock drift detection */
	owl_clock_validator_init(&clock_val, cfg.target_pid);

	/* Initialize vDSO integrity */
	owl_vdso_integrity_init(&vdso_integ, cfg.target_pid);
	if (owl_vdso_integrity_baseline(&vdso_integ, cfg.target_pid) < 0) {
		OWL_WARN("vdso baseline failed (non-fatal)");
	}

	OWL_INFO("ready (pid=%d, target=%d, mode=%s)",
		 getpid(), cfg.target_pid,
		 cfg.enforce ? "enforce" : "observe");

	/* Run the event loop */
	ret = event_loop(dev_fd, bpf, &pipeline, &integrity, &selfprot,
			 &dbg_detect, &clock_val, &vdso_integ,
			 log_file) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;

	OWL_INFO("shutting down (events=%u, blocks=%u, kills=%u, sigs=%u)",
		 pipeline.events_processed, pipeline.actions_block,
		 pipeline.actions_kill, pipeline.sig_matches);

cleanup:
	owl_ptree_destroy(&ptree);
	if (bpf)
		owl_bpf_destroy(bpf);
	if (dev_fd >= 0)
		close(dev_fd);
	if (log_file)
		fclose(log_file);

	return ret;
}
