/*
 * mprotect_inject_via_ptrace - In-process mprotect code injection
 *
 * Realistic attack chain: PTRACE_ATTACH to game, inject syscalls into
 * the game's execution context via register manipulation and single-
 * stepping. The mprotect(RW->RX) call originates from the game's PID,
 * firing the eBPF LSM file_mprotect hook.
 *
 * Steps:
 *   1. PTRACE_ATTACH to game (triggers PTRACE_ATTEMPT if protected)
 *   2. Save registers + instruction at PC
 *   3. Write SVC/syscall instruction at PC
 *   4. Set regs for mmap(RW), single-step to execute
 *   5. Write code bytes to mmap'd page via PTRACE_POKEDATA
 *   6. Set regs for mprotect(RX), single-step (MPROTECT_EXEC trigger)
 *   7. Restore everything, detach
 *
 * Baseline: full chain succeeds, RW->RX in game context.
 * Protected: blocked at step 1 (EPERM) or detected at step 6.
 *
 * Usage: mprotect_inject_via_ptrace [<pid>]
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__aarch64__)
#include <asm/ptrace.h>
#include <linux/elf.h>
#include <sys/uio.h>
#elif defined(__x86_64__)
#include <sys/user.h>
#else
#error "Unsupported architecture"
#endif

#include "../game/game_state.h"

/* Syscall numbers */
#if defined(__aarch64__)
#define NR_MMAP     222
#define NR_MPROTECT 226
#elif defined(__x86_64__)
#define NR_MMAP     9
#define NR_MPROTECT 10
#endif

#define INJ_PAGE_SIZE  4096
#define INJ_PROT_RW    0x3   /* PROT_READ | PROT_WRITE */
#define INJ_PROT_RX    0x5   /* PROT_READ | PROT_EXEC */
#define INJ_MAP_FLAGS  0x22  /* MAP_PRIVATE | MAP_ANONYMOUS */

/* -------------------------------------------------------------------------
 * Game PID discovery
 * ----------------------------------------------------------------------- */

static int parse_pid_from_info(pid_t *pid)
{
	FILE *f = fopen(GAME_INFO_FILE, "r");
	if (!f) {
		fprintf(stderr, "[mprotect_inject] Cannot open %s: %s\n",
			GAME_INFO_FILE, strerror(errno));
		return -1;
	}

	long p;
	char addr_buf[64];
	if (fscanf(f, "%ld %63s", &p, addr_buf) != 2 || p <= 0) {
		fprintf(stderr, "[mprotect_inject] Invalid info file\n");
		fclose(f);
		return -1;
	}
	fclose(f);

	*pid = (pid_t)p;
	return 0;
}

/* -------------------------------------------------------------------------
 * Architecture-specific register handling
 * ----------------------------------------------------------------------- */

#if defined(__aarch64__)

struct saved_state {
	struct user_pt_regs regs;
	long orig_word;
	uint64_t pc;
};

static int save_state(pid_t pid, struct saved_state *s)
{
	struct iovec iov = { .iov_base = &s->regs, .iov_len = sizeof(s->regs) };

	if (ptrace(PTRACE_GETREGSET, pid,
		   (void *)(uintptr_t)NT_PRSTATUS, &iov) < 0)
		return -1;

	s->pc = s->regs.pc;

	errno = 0;
	s->orig_word = ptrace(PTRACE_PEEKDATA, pid,
			      (void *)(uintptr_t)s->pc, NULL);
	if (errno != 0)
		return -1;

	return 0;
}

static int inject_syscall_insn(pid_t pid, const struct saved_state *s)
{
	/* Replace instruction at PC with SVC #0, keep upper 4 bytes */
	long word = (s->orig_word & (long)0xFFFFFFFF00000000UL) |
		    (long)0xD4000001UL;

	return ptrace(PTRACE_POKEDATA, pid,
		      (void *)(uintptr_t)s->pc, (void *)word);
}

static int set_syscall_regs(pid_t pid, uint64_t pc,
			    uint64_t nr, uint64_t a0, uint64_t a1,
			    uint64_t a2, uint64_t a3, uint64_t a4,
			    uint64_t a5)
{
	struct user_pt_regs r;
	struct iovec iov = { .iov_base = &r, .iov_len = sizeof(r) };

	if (ptrace(PTRACE_GETREGSET, pid,
		   (void *)(uintptr_t)NT_PRSTATUS, &iov) < 0)
		return -1;

	r.regs[8] = nr;
	r.regs[0] = a0;
	r.regs[1] = a1;
	r.regs[2] = a2;
	r.regs[3] = a3;
	r.regs[4] = a4;
	r.regs[5] = a5;
	r.pc = pc;

	return ptrace(PTRACE_SETREGSET, pid,
		      (void *)(uintptr_t)NT_PRSTATUS, &iov);
}

static uint64_t read_result(pid_t pid)
{
	struct user_pt_regs r = {0};
	struct iovec iov = { .iov_base = &r, .iov_len = sizeof(r) };

	if (ptrace(PTRACE_GETREGSET, pid,
		   (void *)(uintptr_t)NT_PRSTATUS, &iov) < 0) {
		fprintf(stderr, "[mprotect_inject] read_result failed: %s\n",
			strerror(errno));
		return (uint64_t)-1;
	}
	return r.regs[0];
}

static int restore_state(pid_t pid, const struct saved_state *s)
{
	if (ptrace(PTRACE_POKEDATA, pid,
		   (void *)(uintptr_t)s->pc,
		   (void *)s->orig_word) < 0)
		return -1;

	struct iovec iov = {
		.iov_base = (void *)&s->regs,
		.iov_len = sizeof(s->regs),
	};

	return ptrace(PTRACE_SETREGSET, pid,
		      (void *)(uintptr_t)NT_PRSTATUS, &iov);
}

/* Code word: mov x0, #42; ret */
static const long CODE_WORD = (long)0xD65F03C0D2800540UL;

#elif defined(__x86_64__)

struct saved_state {
	struct user_regs_struct regs;
	long orig_word;
	uint64_t pc;
};

static int save_state(pid_t pid, struct saved_state *s)
{
	if (ptrace(PTRACE_GETREGS, pid, NULL, &s->regs) < 0)
		return -1;

	s->pc = s->regs.rip;

	errno = 0;
	s->orig_word = ptrace(PTRACE_PEEKDATA, pid,
			      (void *)(uintptr_t)s->pc, NULL);
	if (errno != 0)
		return -1;

	return 0;
}

static int inject_syscall_insn(pid_t pid, const struct saved_state *s)
{
	/* Replace low 2 bytes with syscall (0F 05), keep rest */
	long word = (s->orig_word & ~0xFFFFL) | 0x050FL;

	return ptrace(PTRACE_POKEDATA, pid,
		      (void *)(uintptr_t)s->pc, (void *)word);
}

static int set_syscall_regs(pid_t pid, uint64_t pc,
			    uint64_t nr, uint64_t a0, uint64_t a1,
			    uint64_t a2, uint64_t a3, uint64_t a4,
			    uint64_t a5)
{
	struct user_regs_struct r;

	if (ptrace(PTRACE_GETREGS, pid, NULL, &r) < 0)
		return -1;

	r.rax = nr;
	r.rdi = a0;
	r.rsi = a1;
	r.rdx = a2;
	r.r10 = a3;
	r.r8 = a4;
	r.r9 = a5;
	r.rip = pc;

	return ptrace(PTRACE_SETREGS, pid, NULL, &r);
}

static uint64_t read_result(pid_t pid)
{
	struct user_regs_struct r;

	ptrace(PTRACE_GETREGS, pid, NULL, &r);
	return r.rax;
}

static int restore_state(pid_t pid, const struct saved_state *s)
{
	if (ptrace(PTRACE_POKEDATA, pid,
		   (void *)(uintptr_t)s->pc,
		   (void *)s->orig_word) < 0)
		return -1;

	return ptrace(PTRACE_SETREGS, pid, NULL, &s->regs);
}

/*
 * Code word: mov eax, 42 (B8 2A 00 00 00) + ret (C3) + 2 pad bytes.
 * Little-endian: byte[0]=B8 byte[1]=2A ... byte[5]=C3
 */
static const long CODE_WORD = (long)0x0000C30000002AB8L;

#endif /* arch */

/* -------------------------------------------------------------------------
 * Syscall execution
 * ----------------------------------------------------------------------- */

#if defined(__aarch64__)
/*
 * PTRACE_SINGLESTEP over SVC #0 on kernel 6.17 ARM64 does not execute
 * the syscall — the register file is unchanged after the step. Use
 * PTRACE_SYSCALL enter/exit pair instead, which uses the kernel's
 * syscall tracing infrastructure and reliably processes SVC on all
 * ARM64 kernels.
 */
static int exec_syscall_wait(pid_t pid)
{
	int status;

	/* Enter syscall */
	if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0) {
		fprintf(stderr, "[mprotect_inject] PTRACE_SYSCALL (enter) "
			"failed: %s\n", strerror(errno));
		return -1;
	}

	if (waitpid(pid, &status, 0) < 0) {
		fprintf(stderr, "[mprotect_inject] waitpid (enter) "
			"failed: %s\n", strerror(errno));
		return -1;
	}
	if (!WIFSTOPPED(status)) {
		fprintf(stderr, "[mprotect_inject] Target not stopped at "
			"syscall-enter (status=0x%x)\n", status);
		return -1;
	}

	/* Exit syscall */
	if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0) {
		fprintf(stderr, "[mprotect_inject] PTRACE_SYSCALL (exit) "
			"failed: %s\n", strerror(errno));
		return -1;
	}

	if (waitpid(pid, &status, 0) < 0) {
		fprintf(stderr, "[mprotect_inject] waitpid (exit) "
			"failed: %s\n", strerror(errno));
		return -1;
	}
	if (!WIFSTOPPED(status)) {
		fprintf(stderr, "[mprotect_inject] Target not stopped at "
			"syscall-exit (status=0x%x)\n", status);
		return -1;
	}

	return 0;
}
#elif defined(__x86_64__)
static int single_step_wait(pid_t pid)
{
	if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0) {
		fprintf(stderr, "[mprotect_inject] SINGLESTEP failed: %s\n",
			strerror(errno));
		return -1;
	}

	int status;
	if (waitpid(pid, &status, 0) < 0) {
		fprintf(stderr, "[mprotect_inject] waitpid failed: %s\n",
			strerror(errno));
		return -1;
	}

	if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
		return 0;

	if (WIFSIGNALED(status)) {
		fprintf(stderr, "[mprotect_inject] Target killed by signal %d\n",
			WTERMSIG(status));
		return -1;
	}

	fprintf(stderr, "[mprotect_inject] Unexpected stop (status=0x%x, "
		"sig=%d)\n", status,
		WIFSTOPPED(status) ? WSTOPSIG(status) : -1);
	return -1;
}
#endif

/* -------------------------------------------------------------------------
 * Main
 * ----------------------------------------------------------------------- */

int main(int argc, char *argv[])
{
	pid_t target_pid;

	if (argc == 2) {
		char *endptr;
		errno = 0;
		long pid_val = strtol(argv[1], &endptr, 10);
		if (errno != 0 || *endptr != '\0' || pid_val <= 0) {
			fprintf(stderr, "Invalid PID: %s\n", argv[1]);
			return EXIT_FAILURE;
		}
		target_pid = (pid_t)pid_val;
	} else if (argc == 1) {
		if (parse_pid_from_info(&target_pid) != 0)
			return EXIT_FAILURE;
	} else {
		fprintf(stderr, "Usage: %s [<pid>]\n", argv[0]);
		return EXIT_FAILURE;
	}

	printf("[mprotect_inject] Target PID: %d\n", target_pid);
	printf("[mprotect_inject] Attack: ptrace -> mmap(RW) -> write -> "
	       "mprotect(RX)\n\n");

	/* Step 1: PTRACE_ATTACH */
	printf("[mprotect_inject] Step 1: PTRACE_ATTACH...\n");

	if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) < 0) {
		fprintf(stderr, "[mprotect_inject] PTRACE_ATTACH failed: %s\n",
			strerror(errno));
		if (errno == EPERM)
			fprintf(stderr, "[mprotect_inject] Blocked by "
				"anti-cheat (EPERM)\n");
		return EXIT_FAILURE;
	}

	int status;
	if (waitpid(target_pid, &status, 0) < 0) {
		fprintf(stderr, "[mprotect_inject] waitpid failed: %s\n",
			strerror(errno));
		ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
		return EXIT_FAILURE;
	}

	if (!WIFSTOPPED(status)) {
		fprintf(stderr, "[mprotect_inject] Target did not stop\n");
		ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
		return EXIT_FAILURE;
	}

	printf("[mprotect_inject] Attached, target stopped.\n");

	/* Step 2: Save state */
	printf("[mprotect_inject] Step 2: Saving registers + instruction...\n");

	struct saved_state saved;
	if (save_state(target_pid, &saved) < 0) {
		fprintf(stderr, "[mprotect_inject] save_state failed: %s\n",
			strerror(errno));
		ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
		return EXIT_FAILURE;
	}

	printf("[mprotect_inject] Saved PC=0x%lx\n",
	       (unsigned long)saved.pc);

	/* Step 3: Inject syscall instruction at PC */
	printf("[mprotect_inject] Step 3: Injecting syscall instruction...\n");

	if (inject_syscall_insn(target_pid, &saved) < 0) {
		fprintf(stderr, "[mprotect_inject] inject failed: %s\n",
			strerror(errno));
		ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
		return EXIT_FAILURE;
	}

	/* Step 4: Execute mmap(NULL, 4096, RW, PRIVATE|ANON, -1, 0) */
	printf("[mprotect_inject] Step 4: mmap(RW) in game context...\n");

	if (set_syscall_regs(target_pid, saved.pc,
			     NR_MMAP,
			     0,              /* addr = NULL */
			     INJ_PAGE_SIZE,  /* len */
			     INJ_PROT_RW,   /* prot */
			     INJ_MAP_FLAGS,  /* flags */
			     (uint64_t)-1,   /* fd = -1 */
			     0) < 0) {       /* offset */
		fprintf(stderr, "[mprotect_inject] set mmap regs failed: %s\n",
			strerror(errno));
		restore_state(target_pid, &saved);
		ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
		return EXIT_FAILURE;
	}

	if (
#if defined(__aarch64__)
	    exec_syscall_wait(target_pid)
#else
	    single_step_wait(target_pid)
#endif
	    < 0) {
		restore_state(target_pid, &saved);
		ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
		return EXIT_FAILURE;
	}

	uint64_t mmap_addr = read_result(target_pid);
	if ((int64_t)mmap_addr <= 0) {
		fprintf(stderr, "[mprotect_inject] mmap failed in game "
			"(returned 0x%lx)\n", (unsigned long)mmap_addr);
		restore_state(target_pid, &saved);
		ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
		return EXIT_FAILURE;
	}

	printf("[mprotect_inject] mmap'd RW page at 0x%lx in game\n",
	       (unsigned long)mmap_addr);

	/* Step 5: Write code to mmap'd page */
	printf("[mprotect_inject] Step 5: Writing code to page...\n");

	if (ptrace(PTRACE_POKEDATA, target_pid,
		   (void *)(uintptr_t)mmap_addr,
		   (void *)CODE_WORD) < 0) {
		fprintf(stderr, "[mprotect_inject] POKEDATA to mmap page "
			"failed: %s\n", strerror(errno));
		restore_state(target_pid, &saved);
		ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
		return EXIT_FAILURE;
	}

	printf("[mprotect_inject] Code written to game's mmap'd page\n");

	/* Step 6: mprotect(RX) — triggers MPROTECT_EXEC in eBPF LSM */
	printf("[mprotect_inject] Step 6: mprotect(RX) — detection "
	       "trigger...\n");

	if (set_syscall_regs(target_pid, saved.pc,
			     NR_MPROTECT,
			     mmap_addr,      /* addr */
			     INJ_PAGE_SIZE,  /* len */
			     INJ_PROT_RX,    /* prot */
			     0, 0, 0) < 0) {
		fprintf(stderr, "[mprotect_inject] set mprotect regs "
			"failed: %s\n", strerror(errno));
		restore_state(target_pid, &saved);
		ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
		return EXIT_FAILURE;
	}

	if (
#if defined(__aarch64__)
	    exec_syscall_wait(target_pid)
#else
	    single_step_wait(target_pid)
#endif
	    < 0) {
		restore_state(target_pid, &saved);
		ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
		return EXIT_FAILURE;
	}

	uint64_t mprotect_ret = read_result(target_pid);

	printf("[mprotect_inject] mprotect returned: %ld\n",
	       (long)mprotect_ret);

	/* Step 7: Restore and detach */
	printf("[mprotect_inject] Step 7: Restoring game state...\n");

	if (restore_state(target_pid, &saved) < 0)
		fprintf(stderr, "[mprotect_inject] Warning: restore "
			"failed: %s\n", strerror(errno));

	ptrace(PTRACE_DETACH, target_pid, NULL, NULL);

	if ((int64_t)mprotect_ret == 0) {
		printf("[CHEAT] mprotect(RW->RX) succeeded in game PID %d\n",
		       target_pid);
		printf("[mprotect_inject] Full injection chain: ptrace -> "
		       "mmap(RW) -> write -> mprotect(RX)\n");
	} else {
		printf("[mprotect_inject] mprotect denied (ret=%ld)\n",
		       (long)mprotect_ret);
	}

	printf("[mprotect_inject] Done. Detached from target.\n");
	return EXIT_SUCCESS;
}
