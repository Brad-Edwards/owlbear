/*
 * debug_reg_setter - Test cheat using hardware debug registers
 *
 * Attaches to the game via ptrace and sets a hardware breakpoint on
 * a target address. On ARM64, this uses PTRACE_SETREGSET with
 * NT_ARM_HW_BREAK to configure DBGBCR/DBGBVR registers.
 *
 * This should trigger two detections:
 *   1. Ptrace attachment (kprobe on __ptrace_may_access)
 *   2. Debug register activation (ARM64 periodic HW check)
 *
 * Usage: debug_reg_setter <pid> <addr>
 */

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __aarch64__
#include <linux/elf.h>
#include <asm/ptrace.h>

/*
 * ARM64 hardware breakpoint register structure.
 * See linux/perf_regs.h and <asm/hw_breakpoint.h>.
 */
struct arm64_hw_bp {
	uint32_t ctrl;
	uint32_t _pad;
	uint64_t addr;
};

/* DBGBCR control bits for a simple address match breakpoint */
#define HW_BRP_CTRL_ENABLE  (1U << 0)          /* Enable */
#define HW_BRP_CTRL_PMC_EL0 (2U << 1)          /* Match at EL0 */
#define HW_BRP_CTRL_LEN_4   (0xFU << 5)        /* 4-byte match */

static int set_hw_breakpoint(pid_t pid, uint64_t addr)
{
	struct arm64_hw_bp bp;
	struct iovec iov;

	memset(&bp, 0, sizeof(bp));
	bp.addr = addr;
	bp.ctrl = HW_BRP_CTRL_ENABLE | HW_BRP_CTRL_PMC_EL0 | HW_BRP_CTRL_LEN_4;

	iov.iov_base = &bp;
	iov.iov_len = sizeof(bp);

	if (ptrace(PTRACE_SETREGSET, pid, (void *)NT_ARM_HW_BREAK, &iov) < 0) {
		fprintf(stderr, "[debug_reg] PTRACE_SETREGSET failed: %s\n",
			strerror(errno));
		return -1;
	}

	printf("[debug_reg] Hardware breakpoint set at 0x%lx on PID %d\n",
	       (unsigned long)addr, pid);
	return 0;
}
#endif /* __aarch64__ */

static void print_usage(const char *prog)
{
	fprintf(stderr, "Usage: %s <pid> <addr_hex>\n", prog);
	fprintf(stderr, "  pid:      Target process PID\n");
	fprintf(stderr, "  addr_hex: Address for HW breakpoint (e.g., 0x400000)\n");
}

int main(int argc, char *argv[])
{
	pid_t target_pid;
	uint64_t target_addr;
	char *endptr;

	if (argc != 3) {
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	errno = 0;
	long pid_val = strtol(argv[1], &endptr, 10);
	if (errno != 0 || *endptr != '\0' || pid_val <= 0) {
		fprintf(stderr, "Invalid PID: %s\n", argv[1]);
		return EXIT_FAILURE;
	}
	target_pid = (pid_t)pid_val;

	errno = 0;
	target_addr = strtoull(argv[2], &endptr, 16);
	if (errno != 0 || *endptr != '\0') {
		fprintf(stderr, "Invalid address: %s\n", argv[2]);
		return EXIT_FAILURE;
	}

	printf("[debug_reg] Attaching to PID %d...\n", target_pid);

	if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) < 0) {
		if (errno == EPERM)
			fprintf(stderr, "[debug_reg] EPERM — anti-cheat may be blocking ptrace\n");
		else
			fprintf(stderr, "[debug_reg] PTRACE_ATTACH failed: %s\n",
				strerror(errno));
		return EXIT_FAILURE;
	}

	/* Wait for the target to stop */
	int status;
	if (waitpid(target_pid, &status, 0) < 0) {
		fprintf(stderr, "[debug_reg] waitpid failed: %s\n", strerror(errno));
		ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
		return EXIT_FAILURE;
	}

	if (!WIFSTOPPED(status)) {
		fprintf(stderr, "[debug_reg] Target did not stop as expected\n");
		ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
		return EXIT_FAILURE;
	}

	printf("[debug_reg] Attached. Setting HW breakpoint at 0x%lx\n",
	       (unsigned long)target_addr);

#ifdef __aarch64__
	if (set_hw_breakpoint(target_pid, target_addr) < 0) {
		ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
		return EXIT_FAILURE;
	}
#else
	printf("[debug_reg] ARM64 HW breakpoints not available on this arch.\n");
	printf("[debug_reg] On x86, would use PTRACE_POKEUSER for DR0-DR3.\n");
#endif

	/* Keep attached for a few seconds so the HW check catches it */
	printf("[debug_reg] Holding attachment for 10 seconds...\n");
	sleep(10);

	/* Detach */
	ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
	printf("[debug_reg] Detached from PID %d\n", target_pid);

	return EXIT_SUCCESS;
}
