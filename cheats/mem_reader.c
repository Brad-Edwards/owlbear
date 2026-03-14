/*
 * mem_reader - Test cheat using process_vm_readv
 *
 * Reads game state from the target process using the process_vm_readv()
 * syscall. This is the simplest cross-process memory read method on Linux
 * and should be detected by owlbear's kprobe on the syscall.
 *
 * Usage: mem_reader <pid> <state_addr>
 *
 * The state_addr is printed by owlbear-game on startup.
 * Example: mem_reader 1234 0x7fff12345678
 */

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

/* We only need the struct layout, not the full game */
#include "../game/game_state.h"

static volatile sig_atomic_t g_running = 1;

static void signal_handler(int sig)
{
	(void)sig;
	g_running = 0;
}

static int parse_info_file(pid_t *pid, uint64_t *addr)
{
	FILE *f = fopen(GAME_INFO_FILE, "r");
	if (!f) {
		fprintf(stderr, "[mem_reader] Cannot open %s: %s\n",
			GAME_INFO_FILE, strerror(errno));
		return -1;
	}

	long p;
	char addr_buf[64];
	if (fscanf(f, "%ld %63s", &p, addr_buf) != 2 || p <= 0) {
		fprintf(stderr, "[mem_reader] Invalid info file format\n");
		fclose(f);
		return -1;
	}
	fclose(f);

	*pid = (pid_t)p;

	char *endptr;
	errno = 0;
	*addr = strtoull(addr_buf, &endptr, 0);
	if (errno != 0 || (*endptr != '\0' && *endptr != '\n')) {
		fprintf(stderr, "[mem_reader] Invalid address: %s\n", addr_buf);
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
		printf("[mem_reader] Read from info file: PID=%d addr=0x%lx\n",
		       target_pid, (unsigned long)state_addr);
	} else {
		fprintf(stderr, "Usage: %s [<pid> <state_addr>]\n", argv[0]);
		return EXIT_FAILURE;
	}

	/* Install signal handler */
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	printf("[mem_reader] Target PID: %d, State addr: 0x%lx\n",
	       target_pid, (unsigned long)state_addr);
	printf("[mem_reader] Using process_vm_readv() — should trigger detection\n\n");

	struct game_state state;

	while (g_running) {
		struct iovec local_iov = {
			.iov_base = &state,
			.iov_len = sizeof(state),
		};
		struct iovec remote_iov = {
			.iov_base = (void *)(uintptr_t)state_addr,
			.iov_len = sizeof(state),
		};

		ssize_t n = process_vm_readv(target_pid,
					     &local_iov, 1,
					     &remote_iov, 1,
					     0);

		if (n < 0) {
			if (errno == ESRCH) {
				fprintf(stderr, "[mem_reader] Target process "
					"not found (PID %d)\n", target_pid);
				return EXIT_FAILURE;
			}
			if (errno == EPERM) {
				fprintf(stderr, "[mem_reader] Permission denied "
					"— anti-cheat may be blocking\n");
				sleep(1);
				continue;
			}
			fprintf(stderr, "[mem_reader] process_vm_readv failed: "
				"%s\n", strerror(errno));
			return EXIT_FAILURE;
		}

		if ((size_t)n != sizeof(state)) {
			fprintf(stderr, "[mem_reader] Partial read: %zd/%zu\n",
				n, sizeof(state));
			continue;
		}

		/* Verify magic */
		if (state.magic != GAME_STATE_MAGIC) {
			fprintf(stderr, "[mem_reader] Bad magic: 0x%x "
				"(expected 0x%x) — wrong address?\n",
				state.magic, GAME_STATE_MAGIC);
			return EXIT_FAILURE;
		}

		/* Print stolen game state */
		printf("\r[CHEAT] Tick=%u HP=%d/%d Armor=%d "
		       "Pos=(%.0f,%.0f,%.0f) Aim=(%.0f,%.0f) "
		       "Score=%u K/D=%u/%u   ",
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
		fflush(stdout);

		usleep(200000); /* 5 Hz polling */
	}

	printf("\n[mem_reader] Exiting.\n");
	return EXIT_SUCCESS;
}
