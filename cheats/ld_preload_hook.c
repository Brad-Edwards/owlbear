/*
 * ld_preload_hook - Launcher for the LD_PRELOAD cheat
 *
 * Launches owlbear-game with LD_PRELOAD set to preload_hook.so.
 * This is how LD_PRELOAD cheats work in practice: a wrapper script
 * or launcher sets the environment variable before execing the game.
 *
 * Usage: ld_preload_hook <path_to_game> [game_args...]
 *
 * Detection expected:
 *   - eBPF exec tracepoint (new process)
 *   - Library enumeration (preload_hook.so in /proc/pid/maps)
 *   - Function pointer integrity (apply_damage changed)
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void print_usage(const char *prog)
{
	fprintf(stderr, "Usage: %s <path_to_game> [game_args...]\n", prog);
	fprintf(stderr, "\nLaunches the game with LD_PRELOAD=preload_hook.so\n");
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	const char *game_path = argv[1];

	/* Find preload_hook.so relative to this binary */
	char so_path[4096];
	ssize_t len = readlink("/proc/self/exe", so_path, sizeof(so_path) - 1);
	if (len < 0) {
		fprintf(stderr, "readlink failed: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}
	so_path[len] = '\0';

	/* Replace binary name with preload_hook.so */
	char *last_slash = strrchr(so_path, '/');
	if (last_slash) {
		size_t dir_len = (size_t)(last_slash - so_path + 1);
		if (dir_len + strlen("preload_hook.so") >= sizeof(so_path)) {
			fprintf(stderr, "Path too long\n");
			return EXIT_FAILURE;
		}
		strcpy(last_slash + 1, "preload_hook.so");
	} else {
		strncpy(so_path, "preload_hook.so", sizeof(so_path) - 1);
	}

	printf("[ld_preload] Setting LD_PRELOAD=%s\n", so_path);
	printf("[ld_preload] Launching: %s\n", game_path);

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
