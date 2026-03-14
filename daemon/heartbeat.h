/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * heartbeat.h - Heartbeat tracking and watchdog
 *
 * Tracks game heartbeats received over a Unix socket.
 * Detects missed heartbeats (game frozen/killed/tampered).
 */

#ifndef OWLBEAR_HEARTBEAT_H
#define OWLBEAR_HEARTBEAT_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "owlbear_events.h"

/* Heartbeat considered missed after this many seconds */
#define OWL_HB_TIMEOUT_S  5

/* Maximum frame count delta before suspecting tamper */
#define OWL_HB_MAX_FRAME_DELTA  500

/* Heartbeat tracker state */
struct owl_hb_tracker {
	bool     active;          /* Is a game registered? */
	uint32_t game_pid;
	uint32_t last_frame_count;
	uint32_t last_state_hash;
	struct timespec last_received;
	uint32_t missed_count;    /* Consecutive missed heartbeats */
	uint32_t total_received;
};

/**
 * owl_hb_init - Initialize heartbeat tracker
 */
void owl_hb_init(struct owl_hb_tracker *hb);

/**
 * owl_hb_register - Register a game process for heartbeat tracking
 */
void owl_hb_register(struct owl_hb_tracker *hb, uint32_t pid);

/**
 * owl_hb_process - Process an incoming heartbeat message
 * @hb:  Tracker state
 * @msg: Heartbeat message from the game
 *
 * Returns 0 on normal heartbeat.
 * Returns 1 if frame count anomaly detected (frozen or rewound).
 * Returns 2 if state hash changed (potential memory tamper).
 */
int owl_hb_process(struct owl_hb_tracker *hb,
		   const struct owl_heartbeat_game *msg);

/**
 * owl_hb_check_timeout - Check if heartbeat has timed out
 * @hb:  Tracker state
 * @now: Current time
 *
 * Returns true if heartbeat is overdue (game may be dead/frozen).
 */
bool owl_hb_check_timeout(struct owl_hb_tracker *hb,
			  const struct timespec *now);

#endif /* OWLBEAR_HEARTBEAT_H */
