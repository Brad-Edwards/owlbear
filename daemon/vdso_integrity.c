// SPDX-License-Identifier: GPL-2.0-only
/*
 * vdso_integrity.c - vDSO page integrity verification
 *
 * HMAC-SHA256 of the [vdso] mapping for runtime patching detection.
 * Follows the same pattern as integrity.c (maps parsing, /proc/pid/mem
 * reading, buffer variants for testability).
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "vdso_integrity.h"
#include "hmac_sha256.h"

/* -------------------------------------------------------------------------
 * Maps parsing — find [vdso] mapping (pure function)
 * ----------------------------------------------------------------------- */

int owl_vdso_parse_mapping(const char *maps, uint64_t *start, uint64_t *size)
{
	if (!maps || !start || !size)
		return -1;

	const char *line = maps;

	while (*line) {
		/* Check if this line ends with [vdso] */
		const char *nl = strchr(line, '\n');
		size_t line_len = nl ? (size_t)(nl - line) : strlen(line);

		/* Look for "[vdso]" suffix (with possible trailing spaces) */
		const char *vdso = NULL;
		for (size_t i = 0; i + 5 < line_len; i++) {
			if (memcmp(line + i, "[vdso]", 6) == 0) {
				vdso = line + i;
				break;
			}
		}

		if (vdso) {
			uint64_t addr_start, addr_end;

			if (sscanf(line, "%lx-%lx",
				   (unsigned long *)&addr_start,
				   (unsigned long *)&addr_end) == 2) {
				*start = addr_start;
				*size = addr_end - addr_start;
				return 0;
			}
		}

		if (!nl)
			break;
		line = nl + 1;
	}

	return -1;
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
 * Read /proc/<pid>/mem at a given offset
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
 * Public API
 * ----------------------------------------------------------------------- */

int owl_vdso_integrity_init(struct owl_vdso_integrity *ctx, pid_t target)
{
	if (!ctx)
		return -1;

	memset(ctx, 0, sizeof(*ctx));
	ctx->target_pid = target;
	ctx->baseline_set = false;

	return 0;
}

int owl_vdso_integrity_baseline(struct owl_vdso_integrity *ctx, pid_t pid)
{
	if (!ctx || pid <= 0)
		return -1;

	ctx->target_pid = pid;
	ctx->baseline_set = false;

	/* Read /proc/<pid>/maps to find [vdso] */
	char *maps = read_proc_maps(pid);
	if (!maps)
		return -1;

	int ret = owl_vdso_parse_mapping(maps, &ctx->vdso_start,
					 &ctx->vdso_size);
	free(maps);

	if (ret < 0)
		return -1;

	/* Read vDSO pages */
	uint8_t *buf = malloc(ctx->vdso_size);
	if (!buf)
		return -1;

	if (read_proc_mem(pid, ctx->vdso_start, buf, ctx->vdso_size) < 0) {
		free(buf);
		return -1;
	}

	if (owl_vdso_integrity_baseline_buffer(ctx, buf, ctx->vdso_size) < 0) {
		free(buf);
		return -1;
	}
	free(buf);

	char hex[OWL_HMAC_SHA256_LEN * 2 + 1];
	for (size_t i = 0; i < OWL_HMAC_SHA256_LEN; i++)
		sprintf(hex + 2 * i, "%02x", ctx->baseline_hmac[i]);

	printf("owlbeard: vdso baseline: start=0x%lx size=%lu hmac=%s\n",
	       (unsigned long)ctx->vdso_start,
	       (unsigned long)ctx->vdso_size,
	       hex);

	return 0;
}

int owl_vdso_integrity_check(const struct owl_vdso_integrity *ctx)
{
	if (!ctx || !ctx->baseline_set)
		return -1;

	uint8_t *buf = malloc(ctx->vdso_size);
	if (!buf)
		return -1;

	if (read_proc_mem(ctx->target_pid, ctx->vdso_start,
			  buf, ctx->vdso_size) < 0) {
		free(buf);
		return -1;
	}

	int result = owl_vdso_integrity_check_buffer(ctx, buf, ctx->vdso_size);
	free(buf);

	return result;
}

/* -------------------------------------------------------------------------
 * Buffer-based functions (testable without /proc I/O)
 * ----------------------------------------------------------------------- */

int owl_vdso_integrity_baseline_buffer(struct owl_vdso_integrity *ctx,
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

int owl_vdso_integrity_check_buffer(const struct owl_vdso_integrity *ctx,
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
