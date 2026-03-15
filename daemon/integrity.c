// SPDX-License-Identifier: GPL-2.0-only
/*
 * integrity.c - Userspace code integrity verification
 *
 * HMAC-SHA256 of game .text segment for runtime code modification detection.
 * CRC32 retained for heartbeat state_hash.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "integrity.h"
#include "hmac_sha256.h"

/* -------------------------------------------------------------------------
 * CRC32 — standard polynomial 0xEDB88320 (reflected)
 * ----------------------------------------------------------------------- */

uint32_t owl_crc32(const uint8_t *buf, size_t len)
{
	uint32_t crc = 0xFFFFFFFF;

	for (size_t i = 0; i < len; i++) {
		crc ^= buf[i];
		for (int j = 0; j < 8; j++) {
			if (crc & 1)
				crc = (crc >> 1) ^ 0xEDB88320;
			else
				crc >>= 1;
		}
	}

	return ~crc;
}

/* -------------------------------------------------------------------------
 * Maps parsing (pure function)
 * ----------------------------------------------------------------------- */

int owl_integrity_parse_text_segment(const char *maps_content,
				     uint64_t *start, uint64_t *size)
{
	if (!maps_content || !start || !size)
		return -1;

	const char *line = maps_content;

	while (*line) {
		uint64_t addr_start, addr_end;
		char perms[8];

		if (sscanf(line, "%lx-%lx %4s",
			   (unsigned long *)&addr_start,
			   (unsigned long *)&addr_end,
			   perms) == 3) {
			if (perms[0] == 'r' && perms[1] == '-' &&
			    perms[2] == 'x' && perms[3] == 'p') {
				*start = addr_start;
				*size = addr_end - addr_start;
				return 0;
			}
		}

		/* Advance to next line */
		const char *nl = strchr(line, '\n');
		if (!nl)
			break;
		line = nl + 1;
	}

	return -1;
}

/* -------------------------------------------------------------------------
 * Read helper - reads /proc/<pid>/mem at a given offset
 * ----------------------------------------------------------------------- */

static int read_proc_mem(pid_t pid, uint64_t addr, uint8_t *buf, size_t len)
{
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/mem", pid);

	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	if (lseek(fd, (off_t)addr, SEEK_SET) == (off_t)-1) {
		close(fd);
		return -1;
	}

	size_t total = 0;
	while (total < len) {
		ssize_t n = read(fd, buf + total, len - total);
		if (n <= 0) {
			close(fd);
			return -1;
		}
		total += (size_t)n;
	}

	close(fd);
	return 0;
}

/* -------------------------------------------------------------------------
 * Read /proc/<pid>/maps
 * ----------------------------------------------------------------------- */

static char *read_proc_maps(pid_t pid)
{
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/maps", pid);

	FILE *f = fopen(path, "r");
	if (!f)
		return NULL;

	size_t cap = 4096;
	size_t len = 0;
	char *buf = malloc(cap);
	if (!buf) {
		fclose(f);
		return NULL;
	}

	size_t n;
	while ((n = fread(buf + len, 1, cap - len - 1, f)) > 0) {
		len += n;
		if (len >= cap - 1) {
			cap *= 2;
			char *tmp = realloc(buf, cap);
			if (!tmp) {
				free(buf);
				fclose(f);
				return NULL;
			}
			buf = tmp;
		}
	}

	buf[len] = '\0';
	fclose(f);
	return buf;
}

/* -------------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------- */

void owl_integrity_init_ctx(struct owl_integrity *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
}

int owl_integrity_baseline(struct owl_integrity *ctx, pid_t pid)
{
	if (!ctx || pid <= 0)
		return -1;

	ctx->target_pid = pid;
	ctx->baseline_set = false;

	/* Read /proc/<pid>/maps to find .text */
	char *maps = read_proc_maps(pid);
	if (!maps)
		return -1;

	int ret = owl_integrity_parse_text_segment(maps,
						   &ctx->text_start,
						   &ctx->text_size);
	free(maps);

	if (ret < 0)
		return -1;

	/* Cap at 16 MB to avoid excessive memory use */
	if (ctx->text_size > 16 * 1024 * 1024)
		ctx->text_size = 16 * 1024 * 1024;

	/* Read and hash .text */
	uint8_t *buf = malloc(ctx->text_size);
	if (!buf)
		return -1;

	if (read_proc_mem(pid, ctx->text_start, buf, ctx->text_size) < 0) {
		free(buf);
		return -1;
	}

	if (owl_integrity_baseline_buffer(ctx, buf, ctx->text_size) < 0) {
		free(buf);
		return -1;
	}
	free(buf);

	char hex[OWL_HMAC_SHA256_LEN * 2 + 1];
	for (size_t i = 0; i < OWL_HMAC_SHA256_LEN; i++)
		sprintf(hex + 2 * i, "%02x", ctx->baseline_hmac[i]);

	printf("owlbeard: integrity baseline: text=0x%lx size=%lu hmac=%s\n",
	       (unsigned long)ctx->text_start,
	       (unsigned long)ctx->text_size,
	       hex);

	return 0;
}

int owl_integrity_check(const struct owl_integrity *ctx)
{
	if (!ctx || !ctx->baseline_set)
		return -1;

	uint8_t *buf = malloc(ctx->text_size);
	if (!buf)
		return -1;

	if (read_proc_mem(ctx->target_pid, ctx->text_start,
			  buf, ctx->text_size) < 0) {
		free(buf);
		return -1;
	}

	int result = owl_integrity_check_buffer(ctx, buf, ctx->text_size);
	free(buf);

	return result;
}

/* -------------------------------------------------------------------------
 * Buffer-based integrity functions (testable without /proc I/O)
 * ----------------------------------------------------------------------- */

int owl_integrity_baseline_buffer(struct owl_integrity *ctx,
				  const uint8_t *buf, size_t len)
{
	if (!ctx || !buf)
		return -1;

	if (owl_hmac_generate_key(ctx->hmac_key, OWL_HMAC_SHA256_LEN) < 0)
		return -1;

	if (owl_hmac_sha256(ctx->hmac_key, OWL_HMAC_SHA256_LEN,
			    buf, len, ctx->baseline_hmac) < 0)
		return -1;

	ctx->baseline_set = true;
	return 0;
}

int owl_integrity_check_buffer(const struct owl_integrity *ctx,
			       const uint8_t *buf, size_t len)
{
	if (!ctx || !buf || !ctx->baseline_set)
		return -1;

	uint8_t current[OWL_HMAC_SHA256_LEN];

	if (owl_hmac_sha256(ctx->hmac_key, OWL_HMAC_SHA256_LEN,
			    buf, len, current) < 0)
		return -1;

	if (memcmp(current, ctx->baseline_hmac, OWL_HMAC_SHA256_LEN) != 0)
		return 1;  /* Integrity violation */

	return 0;
}
