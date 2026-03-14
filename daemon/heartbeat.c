// SPDX-License-Identifier: GPL-2.0-only
/*
 * heartbeat.c - Heartbeat tracking and watchdog
 */

#include <string.h>
#include <time.h>

#include "heartbeat.h"

void owl_hb_init(struct owl_hb_tracker *hb)
{
	memset(hb, 0, sizeof(*hb));
}

void owl_hb_register(struct owl_hb_tracker *hb, uint32_t pid)
{
	hb->active = true;
	hb->game_pid = pid;
	hb->last_frame_count = 0;
	hb->last_state_hash = 0;
	hb->missed_count = 0;
	hb->total_received = 0;
	clock_gettime(CLOCK_MONOTONIC, &hb->last_received);
}

int owl_hb_process(struct owl_hb_tracker *hb,
		   const struct owl_heartbeat_game *msg)
{
	int result = 0;

	/*
	 * Frame count anomaly detection:
	 *   - Frame count should strictly increase.
	 *   - Same frame count = game frozen / not ticking.
	 *   - Decreased frame count = rewind / tamper.
	 */
	if (hb->total_received > 0) {
		if (msg->frame_count <= hb->last_frame_count)
			result = 1;  /* Frozen or rewound */
	}

	hb->last_frame_count = msg->frame_count;
	hb->last_state_hash = msg->state_hash;
	hb->missed_count = 0;
	hb->total_received++;
	clock_gettime(CLOCK_MONOTONIC, &hb->last_received);

	return result;
}

bool owl_hb_check_timeout(struct owl_hb_tracker *hb,
			  const struct timespec *now)
{
	if (!hb->active)
		return false;

	long elapsed = now->tv_sec - hb->last_received.tv_sec;

	if (elapsed >= OWL_HB_TIMEOUT_S) {
		hb->missed_count++;
		return true;
	}

	return false;
}
