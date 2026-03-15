/*
 * speed_hack - Launcher for the LD_PRELOAD speed hack
 *
 * Launches a game with LD_PRELOAD set to speed_hook.so, which
 * intercepts clock_gettime(CLOCK_MONOTONIC) and returns 2x elapsed time.
 *
 * Usage: speed_hack <path_to_game> [game_args...]
 *
 * Detection expected:
 *   - LD_PRELOAD environment variable (preload_detect -> LIB_UNEXPECTED)
 *   - Clock drift (MONOTONIC vs MONOTONIC_RAW divergence -> CLOCK_DRIFT)
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void print_usage(const char *prog)
{
	fprintf(stderr, "Usage: %s <path_to_game> [game_args...]\n", prog);
	fprintf(stderr, "\nLaunches the game with LD_PRELOAD=speed_hook.so "
		"(2x speed hack)\n");
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	const char *game_path = argv[1];

	/* Find speed_hook.so relative to this binary */
	char so_path[4096];
	ssize_t len = readlink("/proc/self/exe", so_path, sizeof(so_path) - 1);
	if (len < 0) {
		fprintf(stderr, "readlink failed: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}
	so_path[len] = '\0';

	/* Replace binary name with speed_hook.so */
	char *last_slash = strrchr(so_path, '/');
	if (last_slash) {
		size_t dir_len = (size_t)(last_slash - so_path + 1);
		if (dir_len + strlen("speed_hook.so") >= sizeof(so_path)) {
			fprintf(stderr, "Path too long\n");
			return EXIT_FAILURE;
		}
		strcpy(last_slash + 1, "speed_hook.so");
	} else {
		strncpy(so_path, "speed_hook.so", sizeof(so_path) - 1);
	}

	printf("[speed_hack] Setting LD_PRELOAD=%s\n", so_path);
	printf("[speed_hack] Launching: %s\n", game_path);

	if (setenv("LD_PRELOAD", so_path, 1) < 0) {
		fprintf(stderr, "setenv failed: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}

	/* exec the game with remaining arguments */
	execv(game_path, &argv[1]);

	/* Only reached on error */
	fprintf(stderr, "exec failed: %s\n", strerror(errno));
	return EXIT_FAILURE;
}
