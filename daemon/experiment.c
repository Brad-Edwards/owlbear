// SPDX-License-Identifier: GPL-2.0-only
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include "experiment.h"
#include "owlbear_build.h"

int owl_sensor_mask(const char *text, unsigned *mask)
{
	if (!strcmp(text, "none")) { *mask = 0; return 0; }
	if (!strcmp(text, "all")) { *mask = OWL_BPF_ALL; return 0; }
	unsigned value = 0;
	const char *names[] = {"lsm", "trace", "kprobe", "net"};
	while (*text) {
		size_t len = strcspn(text, ",");
		unsigned i;
		for (i = 0; i < 4; i++)
			if (strlen(names[i]) == len && !strncmp(text, names[i], len)) break;
		if (i == 4 || (value & (1u << i))) return -1;
		value |= 1u << i;
		text += len;
		if (*text && !*++text) return -1;
	}
	if (!value) return -1;
	*mask = value;
	return 0;
}

int owl_experiment_open(struct owl_experiment *exp, const char *path)
{
	exp->socket_fd = -1;
	if (!path) return 0;
	struct sockaddr_un addr = {.sun_family = AF_UNIX};
	if (strlen(path) >= sizeof(addr.sun_path)) { errno = ENAMETOOLONG; return -1; }
	/* Require a private parent directory: socket names must not be replaced. */
	char *parent = strdup(path);
	if (!parent) return -1;
	char *slash = strrchr(parent, '/');
	if (slash) *slash = '\0';
	struct stat st;
	int ok = stat(slash ? (*parent ? parent : "/") : ".", &st);
	free(parent);
	if (ok || !S_ISDIR(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 077)) {
		errno = EACCES; return -1;
	}
	strcpy(addr.sun_path, path);
	int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0) return -1;
	mode_t old = umask(077);
	int rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	umask(old);
	if (rc) { close(fd); return -1; }
	if (listen(fd, 4)) { close(fd); unlink(path); return -1; }
	exp->socket_fd = fd;
	exp->socket_path = path;
	return 0;
}

int owl_experiment_poll(struct owl_experiment *exp, int dev_fd)
{
	if (exp->socket_fd < 0) return 0;
	int fd = accept4(exp->socket_fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
	if (fd < 0) return 0;
	struct pollfd pfd = {.fd = fd, .events = POLLIN};
	char request[64];
	ssize_t n = poll(&pfd, 1, 100) > 0 ? recv(fd, request, sizeof(request)-1, MSG_TRUNC) : -1;
	bool valid = n > 0 && n < (ssize_t)sizeof(request);
	if (valid) { request[n] = '\0'; valid = (size_t)n == strlen(request); }
	bool flush = valid && !strcmp(request, "owlbear.control.v1 flush");
	bool reset = valid && !strcmp(request, "owlbear.control.v1 reset");
	bool stop = valid && !strcmp(request, "owlbear.control.v1 stop");
	bool health = valid && !strcmp(request, "owlbear.control.v1 health");
	bool success = health || flush || reset || stop;
	struct owl_pipeline *pipe = exp->pipeline;
	if (flush || stop) {
		/* Bounded drain; producers may continue concurrently. */
		struct owlbear_event ev;
		for (unsigned i = 0; dev_fd >= 0 && i < OWL_EVENT_RING_SIZE; i++) {
			ssize_t size = read(dev_fd, &ev, sizeof(ev));
			if (size < 0 && errno == EAGAIN) break;
			if (size != sizeof(ev)) { success = false; break; }
			owl_pipeline_process(pipe, &ev);
		}
		if (owl_bpf_poll(exp->bpf, 0) < 0) success = false;
		if (!pipe->event_file || fflush(pipe->event_file) ||
		    fsync(fileno(pipe->event_file)) || ferror(pipe->event_file)) success = false;
	}
	if (reset) {
		pipe->events_processed = pipe->actions_block = pipe->actions_kill = pipe->sig_matches = 0;
		pipe->epoch++;
		if (pipe->ptree) { owl_ptree_destroy(pipe->ptree); owl_ptree_init(pipe->ptree); }
	}
	struct owl_status status = {0};
	bool kmod = dev_fd >= 0 && ioctl(dev_fd, OWL_IOC_GET_STATUS, &status) == 0;
	unsigned attached = owl_bpf_attached(exp->bpf);
	bool delivery = !attached || owl_bpf_ringbuf_fd(exp->bpf) >= 0;
	bool ready = delivery && exp->loop_ready && exp->configured && kmod &&
		status.target_pid == (unsigned)pipe->target_pid &&
		status.enforce_mode == exp->enforce && attached == exp->requested &&
		kill(pipe->target_pid, 0) == 0 && pipe->event_file && !ferror(pipe->event_file);
	char reply[2048];
	int len = snprintf(reply, sizeof(reply),
		"{\"schema\":\"owlbear.control.v1\",\"ok\":%s,\"ready\":%s,"
		"\"pid\":%d,\"target_pid\":%d,\"epoch\":%u,"
		"\"requested_bpf\":%u,\"attached_bpf\":%u,\"bpf_configured\":%s,"
		"\"kernel_responsive\":%s,\"kernel_target_pid\":%u,\"kernel_enforce\":%s,"
		"\"requested_enforce\":%s,\"lsm_enforce\":%s,\"events_processed\":%u,"
		"\"kernel_dropped\":%u,\"bpf_dropped\":null,\"evidence_loss_known\":%s,"
		"\"code_integrity_baseline\":%s,\"vdso_baseline\":%s,\"signatures_loaded\":%s,"
		"\"bpf_delivery\":%s,\"output_failed\":%s,\"build\":" OWL_BUILD_INFO_JSON "}\n",
		success ? "true":"false", ready ? "true":"false", getpid(), pipe->target_pid,
		pipe->epoch, exp->requested, attached, exp->configured ? "true":"false",
		kmod ? "true":"false", status.target_pid, status.enforce_mode ? "true":"false",
		exp->enforce ? "true":"false", attached & 1 ? (exp->enforce ? "true":"false") : "null",
		pipe->events_processed, status.events_dropped,
		kmod && !attached ? "true":"false",
		exp->integrity_baseline ? "true":"false", exp->vdso_baseline ? "true":"false",
		exp->signatures_loaded ? "true":"false", delivery ? "true":"false",
		pipe->event_file && !ferror(pipe->event_file) ? "false":"true");
	if (len > 0 && len < (int)sizeof(reply)) send(fd, reply, (size_t)len, MSG_NOSIGNAL);
	close(fd);
	return stop && success;
}

void owl_experiment_close(struct owl_experiment *exp)
{
	if (exp->socket_fd >= 0) { close(exp->socket_fd); unlink(exp->socket_path); }
}
