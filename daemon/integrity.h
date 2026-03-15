/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * integrity.h - Userspace code integrity verification
 *
 * Computes an HMAC-SHA256 of the game's .text segment from /proc/<pid>/mem
 * at baseline using a per-session random key, then periodically re-checks.
 * Any mismatch indicates runtime code modification (code injection,
 * inline hooks, etc.).
 */

#ifndef OWLBEAR_INTEGRITY_H
#define OWLBEAR_INTEGRITY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "hmac_sha256.h"

/* Integrity checker state */
struct owl_integrity {
	pid_t    target_pid;
	uint64_t text_start;                       /* Virtual address of .text */
	uint64_t text_size;                        /* Size of .text in bytes */
	uint8_t  baseline_hmac[OWL_HMAC_SHA256_LEN]; /* HMAC-SHA256 at baseline */
	uint8_t  hmac_key[OWL_HMAC_SHA256_LEN];    /* Per-session random key */
	bool     baseline_set;
};

/**
 * owl_integrity_init_ctx - Initialize integrity checker
 * @ctx: Integrity context
 */
void owl_integrity_init_ctx(struct owl_integrity *ctx);

/**
 * owl_integrity_baseline - Capture baseline .text HMAC-SHA256
 * @ctx: Integrity context
 * @pid: Target PID
 *
 * Parses /proc/<pid>/maps to find the first r-xp segment,
 * reads it via /proc/<pid>/mem, and computes HMAC-SHA256
 * with a fresh random key.
 *
 * Returns 0 on success, -1 on error.
 */
int owl_integrity_baseline(struct owl_integrity *ctx, pid_t pid);

/**
 * owl_integrity_check - Re-verify .text against baseline
 * @ctx: Integrity context (must have baseline set)
 *
 * Returns 0 if .text matches baseline.
 * Returns 1 if .text has changed (integrity violation).
 * Returns -1 on read error.
 */
int owl_integrity_check(const struct owl_integrity *ctx);

/**
 * owl_integrity_baseline_buffer - Capture baseline HMAC-SHA256 of a buffer
 * @ctx: Integrity context
 * @buf: Data buffer
 * @len: Buffer length
 *
 * Generates a random key, computes HMAC-SHA256, stores both.
 * Returns 0 on success, -1 on error.
 */
int owl_integrity_baseline_buffer(struct owl_integrity *ctx,
				  const uint8_t *buf, size_t len);

/**
 * owl_integrity_check_buffer - Verify buffer against stored baseline
 * @ctx: Integrity context (must have baseline set)
 * @buf: Data buffer
 * @len: Buffer length
 *
 * Returns 0 if buffer matches baseline.
 * Returns 1 if buffer has changed (integrity violation).
 * Returns -1 on error.
 */
int owl_integrity_check_buffer(const struct owl_integrity *ctx,
			       const uint8_t *buf, size_t len);

/**
 * owl_crc32 - Compute CRC32 of a buffer
 * @buf: Data buffer
 * @len: Buffer length
 *
 * Returns the CRC32 value. Pure function, testable without I/O.
 */
uint32_t owl_crc32(const uint8_t *buf, size_t len);

/**
 * owl_integrity_parse_text_segment - Find first r-xp mapping in maps
 * @maps_content: Contents of /proc/<pid>/maps
 * @start:        Output: start address
 * @size:         Output: size in bytes
 *
 * Returns 0 on success, -1 if no r-xp segment found.
 * Pure function, testable without /proc.
 */
int owl_integrity_parse_text_segment(const char *maps_content,
				     uint64_t *start, uint64_t *size);

#endif /* OWLBEAR_INTEGRITY_H */
