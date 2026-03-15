/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * hmac_sha256.h - HMAC-SHA256 wrapper for code integrity verification
 *
 * Uses OpenSSL one-shot HMAC() with EVP_sha256().
 * Per-session 256-bit random key from /dev/urandom.
 */

#ifndef OWLBEAR_HMAC_SHA256_H
#define OWLBEAR_HMAC_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define OWL_HMAC_SHA256_LEN 32

/**
 * owl_hmac_sha256 - Compute HMAC-SHA256 of a buffer
 * @key:      HMAC key
 * @key_len:  Key length in bytes
 * @data:     Input data (may be NULL if data_len is 0)
 * @data_len: Input data length
 * @out:      Output buffer (must be at least OWL_HMAC_SHA256_LEN bytes)
 *
 * Returns 0 on success, -1 on error.
 */
int owl_hmac_sha256(const uint8_t *key, size_t key_len,
		    const uint8_t *data, size_t data_len,
		    uint8_t *out);

/**
 * owl_hmac_generate_key - Generate a random key from /dev/urandom
 * @key:     Output buffer
 * @key_len: Number of random bytes to generate
 *
 * Returns 0 on success, -1 on error.
 */
int owl_hmac_generate_key(uint8_t *key, size_t key_len);

#endif /* OWLBEAR_HMAC_SHA256_H */
