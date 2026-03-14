/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * game_state.h - Test game state structures
 *
 * These structures simulate cheat-relevant game internals:
 *   - Mutable values (health, position, score) for value modification
 *   - Function pointers for hook detection
 *   - A vtable-like structure for vtable hook detection
 *
 * The game exports its state address so test cheats know where to look.
 * In a real game, cheats would use memory scanning to find these.
 */

#ifndef GAME_STATE_H
#define GAME_STATE_H

#include <stdint.h>
#include <stdbool.h>

/* -------------------------------------------------------------------------
 * Core game state — the primary cheat target
 * ----------------------------------------------------------------------- */

struct game_player {
	int32_t  health;           /* 0-100, target for value modification */
	int32_t  max_health;
	int32_t  armor;
	int32_t  ammo;
	float    position[3];      /* x, y, z — target for teleport hacks */
	float    velocity[3];      /* vx, vy, vz — target for speedhacks */
	float    aim_angles[2];    /* yaw, pitch — target for aimbot */
	uint32_t score;
	uint32_t kills;
	uint32_t deaths;
	bool     alive;
	uint8_t  _pad[3];
};

/* -------------------------------------------------------------------------
 * Function pointer table — target for function hooking
 * ----------------------------------------------------------------------- */

typedef void (*damage_fn)(struct game_player *player, int32_t amount);
typedef void (*heal_fn)(struct game_player *player, int32_t amount);
typedef void (*move_fn)(struct game_player *player, float dx, float dy, float dz);
typedef int  (*physics_fn)(float x, float y, float z);

struct game_functions {
	damage_fn   apply_damage;
	heal_fn     apply_heal;
	move_fn     apply_movement;
	physics_fn  check_collision;
};

/* -------------------------------------------------------------------------
 * Top-level game state — single instance
 *
 * A cheat looking at this game would:
 *   1. Find this struct by scanning for the magic value
 *   2. Read/write player.health, player.position, etc.
 *   3. Hook funcs.apply_damage to prevent damage
 *   4. Read player.aim_angles and write aimbot values
 * ----------------------------------------------------------------------- */

#define GAME_STATE_MAGIC 0x4F574C42  /* "OWLB" */

struct game_state {
	uint32_t             magic;      /* GAME_STATE_MAGIC — scan target */
	uint32_t             tick;       /* Frame counter */
	struct game_player   player;
	struct game_functions funcs;
	uint64_t             state_addr; /* Address of this struct (for cheats) */
};

/* -------------------------------------------------------------------------
 * Display constants
 * ----------------------------------------------------------------------- */

#define GAME_INFO_FILE     "/tmp/owlbear-game.info"

#define GAME_TICK_MS       100   /* 10 Hz game loop */
#define GAME_MAP_WIDTH     80
#define GAME_MAP_HEIGHT    24
#define GAME_INITIAL_HEALTH 100
#define GAME_INITIAL_AMMO   30

#endif /* GAME_STATE_H */
