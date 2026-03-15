// SPDX-License-Identifier: GPL-2.0-only
/*
 * net_allowlist.c - Static IP allowlist for network monitoring
 *
 * Pure functions, no I/O. Linear scan over a small array.
 * IPs stored in network byte order. Deduplicates on add.
 */

#include <string.h>

#include "net_allowlist.h"

int owl_net_allowlist_init(struct owl_net_allowlist *al)
{
	if (!al)
		return -1;

	memset(al, 0, sizeof(*al));
	return 0;
}

int owl_net_allowlist_add(struct owl_net_allowlist *al, uint32_t ip)
{
	if (!al)
		return -1;

	/* Dedup: if already present, no-op */
	for (int i = 0; i < al->count; i++) {
		if (al->ips[i] == ip)
			return 0;
	}

	if (al->count >= OWL_NET_ALLOWLIST_MAX)
		return -1;

	al->ips[al->count++] = ip;
	return 0;
}

int owl_net_allowlist_remove(struct owl_net_allowlist *al, uint32_t ip)
{
	if (!al)
		return -1;

	for (int i = 0; i < al->count; i++) {
		if (al->ips[i] == ip) {
			/* Swap with last element */
			al->ips[i] = al->ips[al->count - 1];
			al->count--;
			return 0;
		}
	}

	return -1;
}

bool owl_net_allowlist_check(const struct owl_net_allowlist *al, uint32_t ip)
{
	if (!al)
		return false;

	for (int i = 0; i < al->count; i++) {
		if (al->ips[i] == ip)
			return true;
	}

	return false;
}
