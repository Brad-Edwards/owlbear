/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * proc_io.h - Shared /proc filesystem I/O helpers
 *
 * Common routines for reading /proc/<pid>/maps and /proc/<pid>/mem,
 * shared between integrity.c and vdso_integrity.c.
 */

#ifndef OWLBEAR_PROC_IO_H
#define OWLBEAR_PROC_IO_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/**
 * owl_read_proc_maps - Read /proc/<pid>/maps into a heap-allocated string
 * @pid: Process ID
 *
 * Returns a NUL-terminated string (caller must free), or NULL on error.
 */
char *owl_read_proc_maps(pid_t pid);

/**
 * owl_read_proc_mem - Read bytes from /proc/<pid>/mem at a given address
 * @pid:  Process ID
 * @addr: Virtual address to read from
 * @buf:  Output buffer
 * @len:  Number of bytes to read
 *
 * Returns 0 on success, -1 on error.
 */
int owl_read_proc_mem(pid_t pid, uint64_t addr, uint8_t *buf, size_t len);

#endif /* OWLBEAR_PROC_IO_H */
