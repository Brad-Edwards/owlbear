/*
 * ptrace_injector - Test cheat using ptrace PEEKDATA
 *
 * Attaches to the game via PTRACE_ATTACH, reads game_state word-by-word
 * with PTRACE_PEEKDATA, prints the stolen values, then detaches.
 * Single read (ptrace stops the target while attached).
 *
 * Usage: ptrace_injector [<pid> <state_addr>]
 *
 * With no args, reads PID and address from the game info file.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../game/game_state.h"

static int parse_info_file(pid_t *pid, uint64_t *addr)
{
	FILE *f = fopen(GAME_INFO_FILE, "r");
	if (!f) {
		fprintf(stderr, "[ptrace_injector] Cannot open %s: %s\n",
			GAME_INFO_FILE, strerror(errno));
		return -1;
	}

	long p;
	char addr_buf[64];
	if (fscanf(f, "%ld %63s", &p, addr_buf) != 2 || p <= 0) {
		fprintf(stderr, "[ptrace_injector] Invalid info file format\n");
		fclose(f);
		return -1;
	}
	fclose(f);

	*pid = (pid_t)p;

	char *endptr;
	errno = 0;
	*addr = strtoull(addr_buf, &endptr, 0);
	if (errno != 0 || (*endptr != '\0' && *endptr != '\n')) {
		fprintf(stderr, "[ptrace_injector] Invalid address: %s\n",
			addr_buf);
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	pid_t target_pid;
	uint64_t state_addr;
	char *endptr;

	if (argc == 3) {
		errno = 0;
		long pid_val = strtol(argv[1], &endptr, 10);
		if (errno != 0 || *endptr != '\0' || pid_val <= 0) {
			fprintf(stderr, "Invalid PID: %s\n", argv[1]);
			return EXIT_FAILURE;
		}
		target_pid = (pid_t)pid_val;

		errno = 0;
		state_addr = strtoull(argv[2], &endptr, 0);
		if (errno != 0 || *endptr != '\0') {
			fprintf(stderr, "Invalid address: %s\n", argv[2]);
			return EXIT_FAILURE;
		}
	} else if (argc == 1) {
		if (parse_info_file(&target_pid, &state_addr) != 0)
			return EXIT_FAILURE;
	} else {
		fprintf(stderr, "Usage: %s [<pid> <state_addr>]\n", argv[0]);
		return EXIT_FAILURE;
	}

	printf("[ptrace_injector] Target PID: %d, State addr: 0x%lx\n",
	       target_pid, (unsigned long)state_addr);
	printf("[ptrace_injector] Using PTRACE_PEEKDATA — should trigger detection\n\n");

	/* Attach — this stops the target */
	if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) < 0) {
		fprintf(stderr, "[ptrace_injector] PTRACE_ATTACH failed: %s\n",
			strerror(errno));
		return EXIT_FAILURE;
	}

	/* Wait for target to stop */
	int status;
	if (waitpid(target_pid, &status, 0) < 0) {
		fprintf(stderr, "[ptrace_injector] waitpid failed: %s\n",
			strerror(errno));
		ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
		return EXIT_FAILURE;
	}

	if (!WIFSTOPPED(status)) {
		fprintf(stderr, "[ptrace_injector] Target did not stop\n");
		ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
		return EXIT_FAILURE;
	}

	printf("[ptrace_injector] Attached, target stopped. Reading state...\n");

	/* Read game_state word-by-word via PEEKDATA */
	struct game_state state;
	size_t nwords = (sizeof(state) + sizeof(long) - 1) / sizeof(long);
	long *dst = (long *)&state;
	uint64_t addr = state_addr;

	for (size_t i = 0; i < nwords; i++) {
		errno = 0;
		long word = ptrace(PTRACE_PEEKDATA, target_pid,
				   (void *)(uintptr_t)addr, NULL);
		if (errno != 0) {
			fprintf(stderr, "[ptrace_injector] PEEKDATA at 0x%lx "
				"failed: %s\n", (unsigned long)addr,
				strerror(errno));
			ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
			return EXIT_FAILURE;
		}
		dst[i] = word;
		addr += sizeof(long);
	}

	/* Detach — resumes target */
	ptrace(PTRACE_DETACH, target_pid, NULL, NULL);

	/* Verify magic */
	if (state.magic != GAME_STATE_MAGIC) {
		fprintf(stderr, "[ptrace_injector] Bad magic: 0x%x "
			"(expected 0x%x) — wrong address?\n",
			state.magic, GAME_STATE_MAGIC);
		return EXIT_FAILURE;
	}

	/* Print stolen game state */
	printf("[CHEAT] Tick=%u HP=%d/%d Armor=%d "
	       "Pos=(%.0f,%.0f,%.0f) Aim=(%.0f,%.0f) "
	       "Score=%u K/D=%u/%u\n",
	       state.tick,
	       state.player.health,
	       state.player.max_health,
	       state.player.armor,
	       state.player.position[0],
	       state.player.position[1],
	       state.player.position[2],
	       state.player.aim_angles[0],
	       state.player.aim_angles[1],
	       state.player.score,
	       state.player.kills,
	       state.player.deaths);

	printf("[ptrace_injector] Done. Detached from target.\n");
	return EXIT_SUCCESS;
}
