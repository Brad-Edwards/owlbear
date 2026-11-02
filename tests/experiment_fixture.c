// SPDX-License-Identifier: GPL-2.0-only
/* Integration fixture only: a FIFO replaces the module device; BPF is absent. */
#include <stdarg.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include "bpf_loader.h"
static struct owl_status status;
int ioctl(int fd, unsigned long command, ...)
{
	(void)fd;
	va_list args;
	va_start(args, command);
	if (command == OWL_IOC_CLEAR_TARGET) status.target_pid = 0;
	else {
		void *value = va_arg(args, void *);
		if (command == OWL_IOC_SET_TARGET) status.target_pid = *(__u32 *)value;
		else if (command == OWL_IOC_SET_MODE) status.enforce_mode = *(__u32 *)value;
		else if (command == OWL_IOC_GET_STATUS) *(struct owl_status *)value = status;
		else { va_end(args); errno = ENOTTY; return -1; }
	}
	va_end(args);
	return 0;
}
struct owl_bpf_ctx *owl_bpf_init_selected(owl_bpf_event_cb cb, void *data,
                                        unsigned mask, bool enforce)
{ (void)cb; (void)data; (void)mask; (void)enforce; return (void *)1; }
int owl_bpf_configure(struct owl_bpf_ctx *ctx, uint32_t target, uint32_t pid)
{ (void)ctx; (void)target; (void)pid; return 0; }
unsigned owl_bpf_attached(const struct owl_bpf_ctx *ctx) { (void)ctx; return 0; }
int owl_bpf_ringbuf_fd(const struct owl_bpf_ctx *ctx) { (void)ctx; return -1; }
int owl_bpf_poll(struct owl_bpf_ctx *ctx, int timeout) { (void)ctx; (void)timeout; return 0; }
void owl_bpf_destroy(struct owl_bpf_ctx *ctx) { (void)ctx; }
bool owl_bpf_has_lsm(const struct owl_bpf_ctx *ctx) { (void)ctx; return false; }
bool owl_bpf_has_trace(const struct owl_bpf_ctx *ctx) { (void)ctx; return false; }
bool owl_bpf_has_kprobe(const struct owl_bpf_ctx *ctx) { (void)ctx; return false; }
bool owl_bpf_has_net(const struct owl_bpf_ctx *ctx) { (void)ctx; return false; }

int fsync(int fd)
{
	if (getenv("OWL_TEST_FSYNC_FAIL")) { errno = EIO; return -1; }
	return (int)syscall(SYS_fsync, fd);
}
