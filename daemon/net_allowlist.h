/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * net_allowlist.h - Static IP allowlist for network monitoring
 *
 * Pure data structure for checking destination IPs against a
 * known-good list. IPs stored in network byte order.
 */

#ifndef OWLBEAR_NET_ALLOWLIST_H
#define OWLBEAR_NET_ALLOWLIST_H

#include <stdbool.h>
#include <stdint.h>

#define OWL_NET_ALLOWLIST_MAX 64

struct owl_net_allowlist {
	uint32_t ips[OWL_NET_ALLOWLIST_MAX];
	int count;
};

/**
 * owl_net_allowlist_init - Zero the allowlist
 * Returns 0 on success, -1 if al is NULL.
 */
int owl_net_allowlist_init(struct owl_net_allowlist *al);

/**
 * owl_net_allowlist_add - Add an IP (deduplicates)
 * @al: Allowlist
 * @ip: IPv4 address in network byte order
 *
 * Returns 0 on success, -1 if full or NULL.
 */
int owl_net_allowlist_add(struct owl_net_allowlist *al, uint32_t ip);

/**
 * owl_net_allowlist_remove - Remove an IP
 * @al: Allowlist
 * @ip: IPv4 address in network byte order
 *
 * Returns 0 on success, -1 if not found or NULL.
 */
int owl_net_allowlist_remove(struct owl_net_allowlist *al, uint32_t ip);

/**
 * owl_net_allowlist_check - Check if IP is in allowlist
 * Returns true if found, false otherwise.
 */
bool owl_net_allowlist_check(const struct owl_net_allowlist *al, uint32_t ip);

#endif /* OWLBEAR_NET_ALLOWLIST_H */
