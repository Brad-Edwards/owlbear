/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * integrity.h - Userspace code integrity verification
 *
 * Computes a CRC32 hash of the game's .text segment from /proc/<pid>/mem
 * at baseline, then periodically re-checks. Any mismatch indicates
 * runtime code modification (code injection, inline hooks, etc.).
 */

#ifndef OWLBEAR_INTEGRITY_H
#define OWLBEAR_INTEGRITY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* Integrity checker state */
struct owl_integrity {
	pid_t    target_pid;
	uint64_t text_start;    /* Virtual address of .text */
	uint64_t text_size;     /* Size of .text in bytes */
	uint32_t baseline_crc;  /* CRC32 captured at baseline */
	bool     baseline_set;
};

/**
 * owl_integrity_init_ctx - Initialize integrity checker
 * @ctx: Integrity context
 */
void owl_integrity_init_ctx(struct owl_integrity *ctx);

/**
 * owl_integrity_baseline - Capture baseline .text CRC32
 * @ctx: Integrity context
 * @pid: Target PID
 *
 * Parses /proc/<pid>/maps to find the first r-xp segment,
 * reads it via /proc/<pid>/mem, and computes CRC32.
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
