/*
 * preload_hook.so - LD_PRELOAD shared object cheat
 *
 * When loaded via LD_PRELOAD, this intercepts the game's damage
 * function by scanning for the game_state magic value and zeroing
 * the apply_damage function pointer (god mode).
 *
 * This should be detected by:
 *   - Library enumeration (unexpected .so in /proc/pid/maps)
 *   - Code integrity checks (function pointer modified)
 *   - eBPF LSM mmap_file (PROT_EXEC mapping of this .so)
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "../game/game_state.h"

static void noop_damage(struct game_player *player, int32_t amount)
{
	(void)player;
	(void)amount;
	/* God mode: do nothing on damage */
}

/*
 * Constructor runs when the .so is loaded into the process.
 * Scans the process's own memory for the game state magic value,
 * then replaces the damage function pointer.
 */
__attribute__((constructor))
static void preload_init(void)
{
	fprintf(stderr, "[preload_hook] Loaded into PID %d\n", getpid());

	/*
	 * In a real cheat, we'd scan memory for the magic value.
	 * For this test, we use the extern symbol directly since
	 * we're loaded into the same process.
	 */
	extern struct game_state g_state __attribute__((weak));

	if (&g_state == NULL) {
		fprintf(stderr, "[preload_hook] g_state not found "
			"(not loaded into owlbear-game?)\n");
		return;
	}

	if (g_state.magic != GAME_STATE_MAGIC) {
		fprintf(stderr, "[preload_hook] Bad magic: 0x%x\n",
			g_state.magic);
		return;
	}

	/* Replace damage function -> god mode */
	g_state.funcs.apply_damage = noop_damage;
	fprintf(stderr, "[preload_hook] God mode activated "
		"(damage function replaced)\n");
}

__attribute__((destructor))
static void preload_fini(void)
{
	fprintf(stderr, "[preload_hook] Unloaded\n");
}
