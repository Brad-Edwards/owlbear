/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * log.h - Header-only logging macro system for owlbeard
 *
 * Four levels (ERR/WARN/INFO/DBG), runtime + compile-time filtering.
 * Mirrors kernel module's pr_info/pr_warn/pr_err pattern.
 *
 * ERR/WARN -> stderr, INFO/DBG -> stdout.
 * DBG compiles to nothing unless OWL_DEBUG is defined.
 */

#ifndef OWL_LOG_H
#define OWL_LOG_H

#include <stdio.h>

enum owl_log_level {
	OWL_LOG_ERR  = 0,   /* Always shown */
	OWL_LOG_WARN = 1,
	OWL_LOG_INFO = 2,   /* Default */
	OWL_LOG_DBG  = 3,   /* Requires OWL_DEBUG compile flag */
};

extern enum owl_log_level g_owl_log_level;

#define OWL_LOG_(level, stream, fmt, ...)                   \
	do {                                                \
		if ((level) <= g_owl_log_level)              \
			fprintf((stream), "owlbeard: " fmt "\n", \
				##__VA_ARGS__);              \
	} while (0)

#define OWL_ERR(fmt, ...)   OWL_LOG_(OWL_LOG_ERR,  stderr, fmt, ##__VA_ARGS__)
#define OWL_WARN(fmt, ...)  OWL_LOG_(OWL_LOG_WARN, stderr, fmt, ##__VA_ARGS__)
#define OWL_INFO(fmt, ...)  OWL_LOG_(OWL_LOG_INFO, stdout, fmt, ##__VA_ARGS__)

#ifdef OWL_DEBUG
#define OWL_DBG(fmt, ...)   OWL_LOG_(OWL_LOG_DBG,  stdout, fmt, ##__VA_ARGS__)
#else
#define OWL_DBG(fmt, ...)   do { } while (0)
#endif

#endif /* OWL_LOG_H */
