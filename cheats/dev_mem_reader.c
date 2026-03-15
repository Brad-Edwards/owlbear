/*
 * dev_mem_reader - Test cheat using /dev/mem
 *
 * Attempts to open /dev/mem and read the first 256 bytes of physical
 * memory. This bypasses all process-level protections (ptrace hooks,
 * /proc/pid/mem blocks, process_vm_* interception) because it accesses
 * raw physical memory directly.
 *
 * Should be blocked by owlbear's eBPF LSM file_open hook.
 *
 * Also attempts /dev/kmem if /dev/mem is blocked, to verify both
 * paths are covered.
 *
 * Usage: dev_mem_reader
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int try_dev_path(const char *path)
{
	int fd;
	unsigned char buf[256];
	ssize_t n;

	printf("[dev_mem_reader] Opening %s...\n", path);

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		int err = errno;
		fprintf(stderr, "[dev_mem_reader] open(%s) failed: %s (errno=%d)\n",
			path, strerror(err), err);
		return -err;
	}

	n = read(fd, buf, sizeof(buf));
	if (n < 0) {
		int err = errno;
		fprintf(stderr, "[dev_mem_reader] read(%s) failed: %s (errno=%d)\n",
			path, strerror(err), err);
		close(fd);
		return -err;
	}

	printf("[CHEAT] Read %zd bytes from %s\n", n, path);
	close(fd);
	return 0;
}

int main(void)
{
	int rc;

	printf("[dev_mem_reader] Attempting raw physical memory access\n");
	printf("[dev_mem_reader] This should be blocked by eBPF LSM\n\n");

	rc = try_dev_path("/dev/mem");
	if (rc == 0)
		return EXIT_SUCCESS;

	if (rc == -EPERM) {
		fprintf(stderr, "[dev_mem_reader] Blocked by anti-cheat (EPERM)\n");
	} else if (rc == -EACCES) {
		fprintf(stderr, "[dev_mem_reader] Blocked by CONFIG_STRICT_DEVMEM (EACCES)\n");
	} else if (rc == -ENOENT) {
		fprintf(stderr, "[dev_mem_reader] /dev/mem does not exist\n");
	}

	/* Also try /dev/kmem */
	printf("\n");
	rc = try_dev_path("/dev/kmem");
	if (rc == 0)
		return EXIT_SUCCESS;

	if (rc == -EPERM)
		fprintf(stderr, "[dev_mem_reader] /dev/kmem also blocked (EPERM)\n");
	else if (rc == -EACCES)
		fprintf(stderr, "[dev_mem_reader] /dev/kmem blocked by kernel config (EACCES)\n");
	else if (rc == -ENOENT)
		fprintf(stderr, "[dev_mem_reader] /dev/kmem does not exist\n");

	/* Exit 0 if at least one path was accessible, 1 otherwise.
	 * The E2E script checks stderr for EPERM vs EACCES. */
	return EXIT_FAILURE;
}
