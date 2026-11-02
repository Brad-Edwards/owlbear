/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef OWL_EXPERIMENT_H
#define OWL_EXPERIMENT_H
#include <stdbool.h>
#include <stdio.h>
#include "event_pipeline.h"
#include "bpf_loader.h"
struct owl_experiment {
	int socket_fd;
	const char *socket_path;
	unsigned requested;
	bool enforce;
	bool configured;
	bool loop_ready;
	bool integrity_baseline;
	bool vdso_baseline;
	bool signatures_loaded;
	struct owl_pipeline *pipeline;
	struct owl_bpf_ctx *bpf;
};
int owl_sensor_mask(const char *text, unsigned *mask);
int owl_experiment_open(struct owl_experiment *exp, const char *path);
/* Returns 1 for a successful stop request, 0 otherwise. */
int owl_experiment_poll(struct owl_experiment *exp, int dev_fd);
void owl_experiment_close(struct owl_experiment *exp);
#endif
