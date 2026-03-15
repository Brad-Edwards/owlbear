// SPDX-License-Identifier: GPL-2.0-only
/*
 * hmac_sha256.c - HMAC-SHA256 via OpenSSL one-shot HMAC()
 *
 * Uses the non-deprecated HMAC() function (OpenSSL 3.0+).
 * Only HMAC_CTX_* is deprecated; the one-shot variant is stable.
 */

#include <fcntl.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "hmac_sha256.h"

int owl_hmac_sha256(const uint8_t *key, size_t key_len,
		    const uint8_t *data, size_t data_len,
		    uint8_t *out)
{
	if (!key || !out)
		return -1;
	if (!data && data_len > 0)
		return -1;

	unsigned int md_len = 0;
	const uint8_t empty = 0;
	const uint8_t *d = data ? data : &empty;

	unsigned char *result = HMAC(EVP_sha256(), key, (int)key_len,
				     d, data_len, out, &md_len);
	if (!result || md_len != OWL_HMAC_SHA256_LEN)
		return -1;

	return 0;
}

int owl_hmac_generate_key(uint8_t *key, size_t key_len)
{
	if (!key || key_len == 0)
		return -1;

	int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		return -1;

	size_t total = 0;
	while (total < key_len) {
		ssize_t n = read(fd, key + total, key_len - total);
		if (n <= 0) {
			close(fd);
			return -1;
		}
		total += (size_t)n;
	}

	close(fd);
	return 0;
}
