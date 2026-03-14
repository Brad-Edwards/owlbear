/*
 * owlbear-game - Test game for anti-cheat validation
 *
 * A terminal-based "game" using ncurses that simulates cheat-relevant
 * game internals. The game:
 *   - Maintains mutable state (health, position, aim, score)
 *   - Has function pointers that can be hooked
 *   - Loads a shared library (for library verification testing)
 *   - Prints its PID and state address (so cheats know where to look)
 *   - Optionally registers with the anti-cheat daemon
 *
 * Usage:
 *   owlbear-game [--no-curses]
 */

#include <errno.h>
#include <math.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ncurses.h>

#include "game_state.h"

/* -------------------------------------------------------------------------
 * Game logic functions — these are the hook targets
 * ----------------------------------------------------------------------- */

static void game_apply_damage(struct game_player *player, int32_t amount)
{
	if (!player->alive || amount <= 0)
		return;

	/* Armor absorbs 50% of damage */
	int32_t absorbed = 0;
	if (player->armor > 0) {
		absorbed = amount / 2;
		if (absorbed > player->armor)
			absorbed = player->armor;
		player->armor -= absorbed;
	}

	int32_t actual = amount - absorbed;
	player->health -= actual;

	if (player->health <= 0) {
		player->health = 0;
		player->alive = false;
		player->deaths++;
	}
}

static void game_apply_heal(struct game_player *player, int32_t amount)
{
	if (!player->alive || amount <= 0)
		return;

	player->health += amount;
	if (player->health > player->max_health)
		player->health = player->max_health;
}

static void game_apply_movement(struct game_player *player,
				float dx, float dy, float dz)
{
	player->position[0] += dx;
	player->position[1] += dy;
	player->position[2] += dz;

	/* Clamp to map bounds */
	for (int i = 0; i < 3; i++) {
		if (player->position[i] < 0.0f)
			player->position[i] = 0.0f;
		if (player->position[i] > 100.0f)
			player->position[i] = 100.0f;
	}

	player->velocity[0] = dx;
	player->velocity[1] = dy;
	player->velocity[2] = dz;
}

static int game_check_collision(float x, float y, float z)
{
	(void)z;
	/* Simple boundary check */
	if (x < 0 || x > 100 || y < 0 || y > 100)
		return 1;
	return 0;
}

/* -------------------------------------------------------------------------
 * Game state initialization
 * ----------------------------------------------------------------------- */

static struct game_state g_state;

static void game_init(void)
{
	memset(&g_state, 0, sizeof(g_state));

	g_state.magic = GAME_STATE_MAGIC;
	g_state.tick = 0;
	g_state.state_addr = (uint64_t)(uintptr_t)&g_state;

	/* Player init */
	g_state.player.health = GAME_INITIAL_HEALTH;
	g_state.player.max_health = GAME_INITIAL_HEALTH;
	g_state.player.armor = 50;
	g_state.player.ammo = GAME_INITIAL_AMMO;
	g_state.player.position[0] = 50.0f;
	g_state.player.position[1] = 50.0f;
	g_state.player.position[2] = 0.0f;
	g_state.player.aim_angles[0] = 0.0f;
	g_state.player.aim_angles[1] = 0.0f;
	g_state.player.alive = true;

	/* Function pointers — cheat hook targets */
	g_state.funcs.apply_damage = game_apply_damage;
	g_state.funcs.apply_heal = game_apply_heal;
	g_state.funcs.apply_movement = game_apply_movement;
	g_state.funcs.check_collision = game_check_collision;
}

/* -------------------------------------------------------------------------
 * Game simulation - random events each tick
 * ----------------------------------------------------------------------- */

static float randf(float min, float max)
{
	return min + ((float)rand() / (float)RAND_MAX) * (max - min);
}

static void game_tick(void)
{
	g_state.tick++;

	if (!g_state.player.alive) {
		/* Respawn after 30 ticks */
		if (g_state.tick % 30 == 0) {
			g_state.player.health = GAME_INITIAL_HEALTH;
			g_state.player.armor = 50;
			g_state.player.ammo = GAME_INITIAL_AMMO;
			g_state.player.alive = true;
		}
		return;
	}

	/* Random movement */
	float dx = randf(-2.0f, 2.0f);
	float dy = randf(-2.0f, 2.0f);
	g_state.funcs.apply_movement(&g_state.player, dx, dy, 0.0f);

	/* Random aim changes */
	g_state.player.aim_angles[0] += randf(-5.0f, 5.0f);
	g_state.player.aim_angles[1] += randf(-2.0f, 2.0f);

	/* Clamp aim */
	if (g_state.player.aim_angles[0] > 360.0f)
		g_state.player.aim_angles[0] -= 360.0f;
	if (g_state.player.aim_angles[0] < 0.0f)
		g_state.player.aim_angles[0] += 360.0f;
	if (g_state.player.aim_angles[1] > 89.0f)
		g_state.player.aim_angles[1] = 89.0f;
	if (g_state.player.aim_angles[1] < -89.0f)
		g_state.player.aim_angles[1] = -89.0f;

	/* Random damage (simulates getting shot) */
	if (rand() % 10 == 0)
		g_state.funcs.apply_damage(&g_state.player, rand() % 25 + 5);

	/* Random heal (simulates medkit pickup) */
	if (rand() % 20 == 0)
		g_state.funcs.apply_heal(&g_state.player, rand() % 30 + 10);

	/* Random kill (simulates killing an enemy) */
	if (rand() % 15 == 0) {
		g_state.player.kills++;
		g_state.player.score += 100;
		if (g_state.player.ammo > 0)
			g_state.player.ammo--;
	}

	/* Ammo pickup */
	if (rand() % 25 == 0)
		g_state.player.ammo += 10;
}

/* -------------------------------------------------------------------------
 * Ncurses rendering
 * ----------------------------------------------------------------------- */

static volatile sig_atomic_t g_running = 1;

static void signal_handler(int sig)
{
	(void)sig;
	g_running = 0;
}

static void write_info_file(void)
{
	FILE *f = fopen(GAME_INFO_FILE, "w");
	if (!f) {
		fprintf(stderr, "owlbear-game: failed to write %s: %s\n",
			GAME_INFO_FILE, strerror(errno));
		return;
	}
	fprintf(f, "%d 0x%lx\n", getpid(), (unsigned long)&g_state);
	fclose(f);
}

static void remove_info_file(void)
{
	unlink(GAME_INFO_FILE);
}

static void draw_bar(int y, int x, const char *label, int value, int max,
		     int color_pair)
{
	int bar_width = 30;
	int filled = (value * bar_width) / max;

	if (filled < 0) filled = 0;
	if (filled > bar_width) filled = bar_width;

	mvprintw(y, x, "%-8s", label);
	attron(COLOR_PAIR(color_pair));
	for (int i = 0; i < filled; i++)
		addch('|');
	attroff(COLOR_PAIR(color_pair));
	for (int i = filled; i < bar_width; i++)
		addch(' ');
	printw(" %d/%d", value, max);
}

static void render(void)
{
	struct game_player *p = &g_state.player;

	clear();

	/* Header */
	attron(A_BOLD);
	mvprintw(0, 0, "=== Owlbear Test Game ===");
	attroff(A_BOLD);
	mvprintw(0, 40, "PID: %d  Tick: %u", getpid(), g_state.tick);

	/* State address (for cheats to find) */
	mvprintw(1, 0, "State Address: 0x%lx  Size: %zu bytes",
		 (unsigned long)&g_state, sizeof(g_state));

	mvprintw(2, 0, "----------------------------------------"
		       "---------------------------------------");

	/* Health and armor bars */
	if (p->alive) {
		draw_bar(4, 2, "Health", p->health, p->max_health, 1);
		draw_bar(5, 2, "Armor", p->armor, 100, 2);
		draw_bar(6, 2, "Ammo", p->ammo, 100, 3);
	} else {
		attron(COLOR_PAIR(4) | A_BOLD);
		mvprintw(4, 2, "*** DEAD *** (respawning...)");
		attroff(COLOR_PAIR(4) | A_BOLD);
	}

	/* Position and aim */
	mvprintw(8, 2, "Position:  X=%.1f  Y=%.1f  Z=%.1f",
		 p->position[0], p->position[1], p->position[2]);
	mvprintw(9, 2, "Velocity:  VX=%.1f  VY=%.1f  VZ=%.1f",
		 p->velocity[0], p->velocity[1], p->velocity[2]);
	mvprintw(10, 2, "Aim:       Yaw=%.1f  Pitch=%.1f",
		 p->aim_angles[0], p->aim_angles[1]);

	/* Score */
	mvprintw(12, 2, "Score: %u   Kills: %u   Deaths: %u",
		 p->score, p->kills, p->deaths);

	/* Function pointer addresses (for hook detection) */
	mvprintw(14, 0, "----------------------------------------"
		       "---------------------------------------");
	mvprintw(15, 2, "Function Pointers (hook targets):");

	/* Print function pointer addresses — use uintptr_t to avoid
	 * ISO C pedantic warning about function-to-object ptr cast */
	mvprintw(16, 4, "apply_damage:    0x%lx",
		 (unsigned long)(uintptr_t)g_state.funcs.apply_damage);
	mvprintw(17, 4, "apply_heal:      0x%lx",
		 (unsigned long)(uintptr_t)g_state.funcs.apply_heal);
	mvprintw(18, 4, "apply_movement:  0x%lx",
		 (unsigned long)(uintptr_t)g_state.funcs.apply_movement);
	mvprintw(19, 4, "check_collision: 0x%lx",
		 (unsigned long)(uintptr_t)g_state.funcs.check_collision);

	/* Instructions */
	mvprintw(21, 0, "----------------------------------------"
		       "---------------------------------------");
	mvprintw(22, 2, "Press 'q' to quit  |  "
		       "Game state is readable at the address above");

	refresh();
}

/* -------------------------------------------------------------------------
 * Main
 * ----------------------------------------------------------------------- */

int main(int argc, char *argv[])
{
	bool use_curses = true;

	/* Simple arg check */
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--no-curses") == 0)
			use_curses = false;
		else if (strcmp(argv[i], "--help") == 0 ||
			 strcmp(argv[i], "-h") == 0) {
			printf("Usage: %s [--no-curses]\n", argv[0]);
			return 0;
		}
	}

	/* Seed RNG */
	srand((unsigned int)time(NULL) ^ (unsigned int)getpid());

	/* Initialize game */
	game_init();

	/* Print critical info to stderr (visible even in curses mode) */
	fprintf(stderr, "owlbear-game: PID=%d state_addr=0x%lx size=%zu\n",
		getpid(), (unsigned long)&g_state, sizeof(g_state));

	/* Write info file for cheats to discover PID + address */
	write_info_file();

	/* Install signal handlers */
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	if (use_curses) {
		/* Initialize ncurses */
		initscr();
		cbreak();
		noecho();
		nodelay(stdscr, TRUE);
		curs_set(0);
		keypad(stdscr, TRUE);

		if (has_colors()) {
			start_color();
			init_pair(1, COLOR_GREEN, COLOR_BLACK);   /* Health */
			init_pair(2, COLOR_CYAN, COLOR_BLACK);    /* Armor */
			init_pair(3, COLOR_YELLOW, COLOR_BLACK);  /* Ammo */
			init_pair(4, COLOR_RED, COLOR_BLACK);     /* Dead */
		}

		while (g_running) {
			int ch = getch();
			if (ch == 'q' || ch == 'Q')
				break;

			game_tick();
			render();

			usleep(GAME_TICK_MS * 1000);
		}

		endwin();
	} else {
		/* Non-curses mode: print state to stdout */
		printf("owlbear-game running (PID %d, state at 0x%lx)\n",
		       getpid(), (unsigned long)&g_state);
		printf("Press Ctrl+C to stop.\n\n");

		while (g_running) {
			game_tick();

			printf("\rTick=%u HP=%d/%d Armor=%d Pos=(%.0f,%.0f) "
			       "Aim=(%.0f,%.0f) K/D=%u/%u Score=%u   ",
			       g_state.tick,
			       g_state.player.health,
			       g_state.player.max_health,
			       g_state.player.armor,
			       g_state.player.position[0],
			       g_state.player.position[1],
			       g_state.player.aim_angles[0],
			       g_state.player.aim_angles[1],
			       g_state.player.kills,
			       g_state.player.deaths,
			       g_state.player.score);
			fflush(stdout);

			usleep(GAME_TICK_MS * 1000);
		}
		printf("\n");
	}

	remove_info_file();

	printf("owlbear-game: exiting (ticks=%u, score=%u)\n",
	       g_state.tick, g_state.player.score);

	return 0;
}
