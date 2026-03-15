/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * vdso_integrity.h - vDSO page integrity verification
 *
 * Computes HMAC-SHA256 of the [vdso] mapping at baseline, then
 * periodically re-checks. Patching the vDSO page is a common
 * speed hack vector — replacing clock_gettime to return accelerated
 * time without LD_PRELOAD detection.
 */

#ifndef OWLBEAR_VDSO_INTEGRITY_H
#define OWLBEAR_VDSO_INTEGRITY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "hmac_sha256.h"

/* vDSO integrity checker state */
struct owl_vdso_integrity {
	pid_t    target_pid;
	uint64_t vdso_start;
	uint64_t vdso_size;
	uint8_t  baseline_hmac[OWL_HMAC_SHA256_LEN];
	uint8_t  hmac_key[OWL_HMAC_SHA256_LEN];
	bool     baseline_set;
};

/**
 * owl_vdso_integrity_init - Initialize vDSO integrity context
 * @ctx:    Integrity context
 * @target: PID to monitor
 *
 * Returns 0 on success, -1 on null context.
 */
int owl_vdso_integrity_init(struct owl_vdso_integrity *ctx, pid_t target);

/**
 * owl_vdso_parse_mapping - Find [vdso] mapping in /proc/pid/maps content
 * @maps:  Contents of /proc/<pid>/maps
 * @start: Output: start address
 * @size:  Output: size in bytes
 *
 * Pure function, testable without /proc.
 * Returns 0 on success, -1 if [vdso] not found.
 */
int owl_vdso_parse_mapping(const char *maps, uint64_t *start, uint64_t *size);

/**
 * owl_vdso_integrity_baseline - Capture baseline vDSO HMAC-SHA256
 * @ctx: Integrity context
 * @pid: Target PID
 *
 * Reads /proc/<pid>/maps to find [vdso], reads it via /proc/<pid>/mem,
 * computes HMAC-SHA256 with a fresh random key.
 *
 * Returns 0 on success, -1 on error.
 */
int owl_vdso_integrity_baseline(struct owl_vdso_integrity *ctx, pid_t pid);

/**
 * owl_vdso_integrity_check - Re-verify vDSO against baseline
 * @ctx: Integrity context (must have baseline set)
 *
 * Returns 0 if vDSO matches baseline.
 * Returns 1 if vDSO has changed (integrity violation).
 * Returns -1 on read error.
 */
int owl_vdso_integrity_check(const struct owl_vdso_integrity *ctx);

/**
 * owl_vdso_integrity_baseline_buffer - Capture baseline of a buffer
 * @ctx: Integrity context
 * @buf: Data buffer
 * @len: Buffer length
 *
 * Testable without /proc I/O.
 * Returns 0 on success, -1 on error.
 */
int owl_vdso_integrity_baseline_buffer(struct owl_vdso_integrity *ctx,
				       const uint8_t *buf, size_t len);

/**
 * owl_vdso_integrity_check_buffer - Verify buffer against stored baseline
 * @ctx: Integrity context (must have baseline set)
 * @buf: Data buffer
 * @len: Buffer length
 *
 * Returns 0 if buffer matches baseline.
 * Returns 1 if buffer has changed (integrity violation).
 * Returns -1 on error.
 */
int owl_vdso_integrity_check_buffer(const struct owl_vdso_integrity *ctx,
				    const uint8_t *buf, size_t len);

#endif /* OWLBEAR_VDSO_INTEGRITY_H */
