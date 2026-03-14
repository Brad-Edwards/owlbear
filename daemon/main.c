// SPDX-License-Identifier: GPL-2.0-only
/*
 * owlbeard - Owlbear anti-cheat userspace daemon
 *
 * Opens /dev/owlbear, sets the target PID, and reads detection events
 * from the kernel module. Events are logged to stdout (structured) and
 * optionally to a log file.
 *
 * Usage:
 *   owlbeard --target <pid> [--enforce] [--log <path>]
 *   owlbeard --help
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

#include "owlbear_events.h"

/* -------------------------------------------------------------------------
 * Configuration
 * ----------------------------------------------------------------------- */

struct daemon_config {
	pid_t       target_pid;
	bool        enforce;
	const char *log_path;
	const char *device_path;
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
		perror("sigaction(SIGINT)");
		return -1;
	}
	if (sigaction(SIGTERM, &sa, NULL) < 0) {
		perror("sigaction(SIGTERM)");
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
		fprintf(stderr, "owlbeard: failed to open %s: %s\n",
			path, strerror(errno));
		if (errno == ENOENT)
			fprintf(stderr, "  Is the owlbear kernel module loaded?\n");
		else if (errno == EACCES)
			fprintf(stderr, "  Try running as root.\n");
	}

	return fd;
}

static int set_target_pid(int fd, pid_t pid)
{
	__u32 p = (__u32)pid;

	if (ioctl(fd, OWL_IOC_SET_TARGET, &p) < 0) {
		fprintf(stderr, "owlbeard: failed to set target PID %d: %s\n",
			pid, strerror(errno));
		return -1;
	}

	printf("owlbeard: protecting PID %d\n", pid);
	return 0;
}

static int set_enforce_mode(int fd, bool enforce)
{
	__u32 mode = enforce ? 1 : 0;

	if (ioctl(fd, OWL_IOC_SET_MODE, &mode) < 0) {
		fprintf(stderr, "owlbeard: failed to set enforce mode: %s\n",
			strerror(errno));
		return -1;
	}

	printf("owlbeard: enforcement mode: %s\n",
	       enforce ? "BLOCK" : "OBSERVE");
	return 0;
}

static int print_status(int fd)
{
	struct owl_status status;

	if (ioctl(fd, OWL_IOC_GET_STATUS, &status) < 0) {
		fprintf(stderr, "owlbeard: failed to get status: %s\n",
			strerror(errno));
		return -1;
	}

	printf("owlbeard: status:\n");
	printf("  target_pid:    %u\n", status.target_pid);
	printf("  enforce_mode:  %s\n", status.enforce_mode ? "block" : "observe");
	printf("  events_total:  %u\n", status.events_generated);
	printf("  events_dropped: %u\n", status.events_dropped);
	printf("  kmod_version:  %u.%u.%u\n",
	       (status.kmod_version >> 16) & 0xFF,
	       (status.kmod_version >> 8) & 0xFF,
	       status.kmod_version & 0xFF);

	return 0;
}

/* -------------------------------------------------------------------------
 * Event loop
 * ----------------------------------------------------------------------- */

static int event_loop(int dev_fd, FILE *log_file)
{
	struct owlbear_event event;
	ssize_t n;

	printf("owlbeard: listening for events...\n");

	while (g_running) {
		n = read(dev_fd, &event, sizeof(event));

		if (n < 0) {
			if (errno == EINTR)
				continue;  /* Signal interrupted read */
			fprintf(stderr, "owlbeard: read error: %s\n",
				strerror(errno));
			return -1;
		}

		if (n == 0) {
			/* EOF - device closed unexpectedly */
			fprintf(stderr, "owlbeard: device closed (module unloaded?)\n");
			return -1;
		}

		if ((size_t)n != sizeof(event)) {
			fprintf(stderr, "owlbeard: partial read: %zd/%zu bytes\n",
				n, sizeof(event));
			continue;
		}

		/* Print to stdout */
		print_event(&event, stdout);

		/* Optionally log to file */
		if (log_file)
			print_event(&event, log_file);
	}

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
		"  -h, --help           Show this help\n"
		"\n"
		"Example:\n"
		"  %s --target $(pidof owlbear-game) --enforce --log /var/log/owlbear.log\n",
		progname, progname);
}

static int parse_args(int argc, char *argv[], struct daemon_config *cfg)
{
	static const struct option long_opts[] = {
		{ "target",  required_argument, NULL, 't' },
		{ "enforce", no_argument,       NULL, 'e' },
		{ "log",     required_argument, NULL, 'l' },
		{ "device",  required_argument, NULL, 'd' },
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

	while ((opt = getopt_long(argc, argv, "t:el:d:h", long_opts, NULL)) != -1) {
		switch (opt) {
		case 't':
			errno = 0;
			pid_val = strtol(optarg, &endptr, 10);
			if (errno != 0 || *endptr != '\0' || pid_val <= 0) {
				fprintf(stderr, "owlbeard: invalid PID: %s\n", optarg);
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
		case 'h':
			print_usage(argv[0]);
			exit(0);
		default:
			print_usage(argv[0]);
			return -1;
		}
	}

	if (cfg->target_pid == 0) {
		fprintf(stderr, "owlbeard: --target <pid> is required\n");
		print_usage(argv[0]);
		return -1;
	}

	return 0;
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

	if (parse_args(argc, argv, &cfg) < 0)
		return EXIT_FAILURE;

	if (install_signal_handlers() < 0)
		return EXIT_FAILURE;

	/* Open log file if requested */
	if (cfg.log_path) {
		log_file = fopen(cfg.log_path, "a");
		if (!log_file) {
			fprintf(stderr, "owlbeard: failed to open log %s: %s\n",
				cfg.log_path, strerror(errno));
			return EXIT_FAILURE;
		}
		setlinebuf(log_file);
		printf("owlbeard: logging to %s\n", cfg.log_path);
	}

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

	printf("owlbeard: ready (pid=%d, target=%d, mode=%s)\n",
	       getpid(), cfg.target_pid,
	       cfg.enforce ? "enforce" : "observe");

	/* Run the event loop */
	ret = event_loop(dev_fd, log_file) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;

	printf("owlbeard: shutting down\n");

cleanup:
	if (dev_fd >= 0)
		close(dev_fd);
	if (log_file)
		fclose(log_file);

	return ret;
}
