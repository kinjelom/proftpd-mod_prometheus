/*
 * ProFTPD - mod_prometheus metric API
 * Copyright (c) 2021 TJ Saunders
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 */

#ifndef MOD_PROMETHEUS_METRIC_H
#define MOD_PROMETHEUS_METRIC_H

#include "mod_prometheus.h"
#include "registry.h"

struct prom_metric;

/* Returns the metric name. */
const char *prom_metric_get_name(struct prom_metric *metric);

/* Returns the text for the metric. */
const char *prom_metric_get_text(pool *p, struct prom_metric *metric);

/* XXX Should we use a table for labels, rather than a list?  The
 * prometheus-client-c code made some naive assumptions about label keys at
 * metric creation time, and ordering of label values at metric sampling time.
 * I guess it depends on how much you trust the code; mod_prometheus can
 * use those same assumptions, since it's NOT a library.  However, this
 * naive approach does not handle cases of new labels added only at sampling
 * time -- that's the problem, and why using a table is probably better.
 */

/* Increment the specified metric ID. */
int prom_metric_incr_value(pool *p, struct prom_metric *metric,
  int32_t incr, pr_table_t *labels);

struct prom_metric *prom_metric_create(pool *p, const char *name);
int prom_metric_destroy(pool *p, struct prom_metric *metric);

int prom_metric_init(pool *p, const char *tables_path,
  struct prom_registry *registry);
int prom_metric_free(pool *p);

#endif /* MOD_PROMETHEUS_METRIC_H */
