/*
 * ptrace_writer - Test cheat using PTRACE_ATTACH + PTRACE_POKEDATA
 *
 * Attaches to the game, writes health=9999 via PTRACE_POKEDATA.
 * Should trigger OWL_EVENT_PTRACE_ATTEMPT. With eBPF LSM active,
 * PTRACE_ATTACH returns -EPERM.
 *
 * Usage: ptrace_writer [<pid> <state_addr>]
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
		fprintf(stderr, "[ptrace_writer] Cannot open %s: %s\n",
			GAME_INFO_FILE, strerror(errno));
		return -1;
	}

	long p;
	char addr_buf[64];
	if (fscanf(f, "%ld %63s", &p, addr_buf) != 2 || p <= 0) {
		fprintf(stderr, "[ptrace_writer] Invalid info file format\n");
		fclose(f);
		return -1;
	}
	fclose(f);

	*pid = (pid_t)p;
	char *endptr;
	errno = 0;
	*addr = strtoull(addr_buf, &endptr, 0);
	if (errno != 0 || (*endptr != '\0' && *endptr != '\n')) {
		fprintf(stderr, "[ptrace_writer] Invalid address: %s\n",
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

	printf("[ptrace_writer] Target PID: %d, State addr: 0x%lx\n",
	       target_pid, (unsigned long)state_addr);
	printf("[ptrace_writer] Will write health=9999 via PTRACE_POKEDATA\n\n");

	/* Attach */
	if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) < 0) {
		fprintf(stderr, "[ptrace_writer] PTRACE_ATTACH failed: %s\n",
			strerror(errno));
		if (errno == EPERM)
			fprintf(stderr, "[ptrace_writer] Blocked by anti-cheat (EPERM)\n");
		return EXIT_FAILURE;
	}

	int status;
	if (waitpid(target_pid, &status, 0) < 0) {
		fprintf(stderr, "[ptrace_writer] waitpid failed: %s\n",
			strerror(errno));
		ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
		return EXIT_FAILURE;
	}

	if (!WIFSTOPPED(status)) {
		fprintf(stderr, "[ptrace_writer] Target did not stop\n");
		ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
		return EXIT_FAILURE;
	}

	printf("[ptrace_writer] Attached, target stopped.\n");

	/*
	 * Write health=9999. The health field is at offset:
	 *   magic (4) + tick (4) + health (4) = offset 8 in game_state
	 * But game_player starts after magic+tick, so:
	 *   offsetof(game_state, player.health) = 8
	 */
	uint64_t health_addr = state_addr + 8;  /* offsetof(game_state, player.health) */

	/* Read current word at health address first */
	errno = 0;
	long word = ptrace(PTRACE_PEEKDATA, target_pid,
			   (void *)(uintptr_t)health_addr, NULL);
	if (errno != 0) {
		fprintf(stderr, "[ptrace_writer] PEEKDATA failed: %s\n",
			strerror(errno));
		ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
		return EXIT_FAILURE;
	}

	/* Replace the low 32 bits (health field) with 9999 */
	int32_t *health_ptr = (int32_t *)&word;
	printf("[ptrace_writer] Current health: %d\n", *health_ptr);
	*health_ptr = 9999;

	/* Write modified word back */
	if (ptrace(PTRACE_POKEDATA, target_pid,
		   (void *)(uintptr_t)health_addr, (void *)word) < 0) {
		fprintf(stderr, "[ptrace_writer] POKEDATA failed: %s\n",
			strerror(errno));
		ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
		return EXIT_FAILURE;
	}

	printf("[ptrace_writer] Wrote health=9999 at 0x%lx\n",
	       (unsigned long)health_addr);

	ptrace(PTRACE_DETACH, target_pid, NULL, NULL);

	printf("[CHEAT] health=9999 written via PTRACE_POKEDATA\n");
	printf("[ptrace_writer] Done. Detached.\n");
	return EXIT_SUCCESS;
}
