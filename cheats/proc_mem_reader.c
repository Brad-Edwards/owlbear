/*
 * proc_mem_reader - Test cheat using /proc/<pid>/mem
 *
 * Reads game state by opening /proc/<pid>/mem and seeking to the
 * game state address. This is the file-based equivalent of
 * process_vm_readv and should be detected by owlbear's kprobe
 * on mem_open.
 *
 * Usage: proc_mem_reader <pid> <state_addr>
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
		fprintf(stderr, "[proc_mem_reader] Cannot open %s: %s\n",
			GAME_INFO_FILE, strerror(errno));
		return -1;
	}

	long p;
	char addr_buf[64];
	if (fscanf(f, "%ld %63s", &p, addr_buf) != 2 || p <= 0) {
		fprintf(stderr, "[proc_mem_reader] Invalid info file format\n");
		fclose(f);
		return -1;
	}
	fclose(f);

	*pid = (pid_t)p;

	char *endptr;
	errno = 0;
	*addr = strtoull(addr_buf, &endptr, 0);
	if (errno != 0 || (*endptr != '\0' && *endptr != '\n')) {
		fprintf(stderr, "[proc_mem_reader] Invalid address: %s\n",
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
	char path[64];
	int mem_fd = -1;
	int ret = EXIT_FAILURE;

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
		printf("[proc_mem_reader] Read from info file: PID=%d addr=0x%lx\n",
		       target_pid, (unsigned long)state_addr);
	} else {
		fprintf(stderr, "Usage: %s [<pid> <state_addr>]\n", argv[0]);
		return EXIT_FAILURE;
	}

	/* Signal handling */
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	/* Open /proc/<pid>/mem — this is the detection trigger */
	snprintf(path, sizeof(path), "/proc/%d/mem", target_pid);

	printf("[proc_mem_reader] Opening %s — should trigger detection\n", path);

	mem_fd = open(path, O_RDONLY);
	if (mem_fd < 0) {
		if (errno == EACCES || errno == EPERM)
			fprintf(stderr, "[proc_mem_reader] Permission denied "
				"— anti-cheat may be blocking\n");
		else
			fprintf(stderr, "[proc_mem_reader] Failed to open %s: "
				"%s\n", path, strerror(errno));
		return EXIT_FAILURE;
	}

	printf("[proc_mem_reader] Target PID: %d, State addr: 0x%lx\n",
	       target_pid, (unsigned long)state_addr);
	printf("[proc_mem_reader] Using /proc/pid/mem — should trigger detection\n\n");

	struct game_state state;

	while (g_running) {
		/* Seek to the game state address */
		off_t offset = (off_t)state_addr;
		if (lseek(mem_fd, offset, SEEK_SET) == (off_t)-1) {
			fprintf(stderr, "[proc_mem_reader] lseek failed: %s\n",
				strerror(errno));
			goto cleanup;
		}

		/* Read the game state */
		ssize_t n = read(mem_fd, &state, sizeof(state));
		if (n < 0) {
			if (errno == EIO) {
				fprintf(stderr, "[proc_mem_reader] EIO — page "
					"not accessible\n");
				sleep(1);
				continue;
			}
			fprintf(stderr, "[proc_mem_reader] read failed: %s\n",
				strerror(errno));
			goto cleanup;
		}

		if ((size_t)n != sizeof(state)) {
			fprintf(stderr, "[proc_mem_reader] Partial read: "
				"%zd/%zu\n", n, sizeof(state));
			continue;
		}

		/* Verify magic */
		if (state.magic != GAME_STATE_MAGIC) {
			fprintf(stderr, "[proc_mem_reader] Bad magic: 0x%x\n",
				state.magic);
			goto cleanup;
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

	ret = EXIT_SUCCESS;
	printf("\n[proc_mem_reader] Exiting.\n");

cleanup:
	if (mem_fd >= 0)
		close(mem_fd);
	return ret;
}
