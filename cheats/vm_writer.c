/*
 * vm_writer - Test cheat using process_vm_writev
 *
 * Writes health=9999 to the game using process_vm_writev().
 * Should trigger OWL_EVENT_VM_WRITEV_ATTEMPT via the eBPF
 * tracepoint on sys_enter_process_vm_writev.
 *
 * Usage: vm_writer [<pid> <state_addr>]
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#include "../game/game_state.h"

static int parse_info_file(pid_t *pid, uint64_t *addr)
{
	FILE *f = fopen(GAME_INFO_FILE, "r");
	if (!f) {
		fprintf(stderr, "[vm_writer] Cannot open %s: %s\n",
			GAME_INFO_FILE, strerror(errno));
		return -1;
	}

	long p;
	char addr_buf[64];
	if (fscanf(f, "%ld %63s", &p, addr_buf) != 2 || p <= 0) {
		fprintf(stderr, "[vm_writer] Invalid info file format\n");
		fclose(f);
		return -1;
	}
	fclose(f);

	*pid = (pid_t)p;
	char *endptr;
	errno = 0;
	*addr = strtoull(addr_buf, &endptr, 0);
	if (errno != 0 || (*endptr != '\0' && *endptr != '\n')) {
		fprintf(stderr, "[vm_writer] Invalid address: %s\n", addr_buf);
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

	printf("[vm_writer] Target PID: %d, State addr: 0x%lx\n",
	       target_pid, (unsigned long)state_addr);
	printf("[vm_writer] Will write health=9999 via process_vm_writev\n\n");

	/*
	 * Write health=9999 at offsetof(game_state, player.health) = 8.
	 */
	int32_t new_health = 9999;
	uint64_t health_addr = state_addr + 8;

	struct iovec local_iov = {
		.iov_base = &new_health,
		.iov_len = sizeof(new_health),
	};
	struct iovec remote_iov = {
		.iov_base = (void *)(uintptr_t)health_addr,
		.iov_len = sizeof(new_health),
	};

	ssize_t n = process_vm_writev(target_pid,
				       &local_iov, 1,
				       &remote_iov, 1,
				       0);
	if (n < 0) {
		fprintf(stderr, "[vm_writer] process_vm_writev failed: %s\n",
			strerror(errno));
		if (errno == EPERM)
			fprintf(stderr, "[vm_writer] Blocked by anti-cheat (EPERM)\n");
		return EXIT_FAILURE;
	}

	if ((size_t)n != sizeof(new_health)) {
		fprintf(stderr, "[vm_writer] Partial write: %zd/%zu\n",
			n, sizeof(new_health));
		return EXIT_FAILURE;
	}

	printf("[CHEAT] health=9999 written via process_vm_writev\n");
	printf("[vm_writer] Done.\n");
	return EXIT_SUCCESS;
}
