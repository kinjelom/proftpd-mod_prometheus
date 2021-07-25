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
#include "prometheus/db.h"

struct prom_metric;

struct prom_metric *prom_metric_create(pool *p, const char *name,
  struct prom_dbh *dbh);
int prom_metric_destroy(pool *p, struct prom_metric *metric);

int prom_metric_add_counter(struct prom_metric *metric, const char *suffix,
  const char *help_text);
int prom_metric_add_gauge(struct prom_metric *metric, const char *suffix,
  const char *help_text);
int prom_metric_add_histogram(struct prom_metric *metric, const char *suffix,
  const char *help_text);
int prom_metric_set_dbh(struct prom_metric *metric, struct prom_dbh *dbh);

/* Returns the metric name. */
const char *prom_metric_get_name(struct prom_metric *metric);

/* Decrement the specified metric by the given `decr`; applies to any
 * gauge records associated with this metric.
 */
int prom_metric_decr(pool *p, const struct prom_metric *metric, uint32_t decr,
  pr_table_t *labels);

/* Increment the specified metric by the given `incr`; applies to any
 * counter/gauge records associated with this metric.
 */
int prom_metric_incr(pool *p, const struct prom_metric *metric, uint32_t incr,
  pr_table_t *labels);

/* Increment the specified metric type by the given `incr`. */
int prom_metric_incr_type(pool *p, const struct prom_metric *metric,
  uint32_t incr, pr_table_t *labels, int metric_type);

/* Observe the specified metric by the given `val`; apply to any
 * histogram records associated with this metric.
 */
int prom_metric_observe(pool *p, const struct prom_metric *metric, double val,
  pr_table_t *labels);

/* Setl the specified metric by the given `val`; applies to any
 * gauge records associated with this metric.
 */
int prom_metric_set(pool *p, const struct prom_metric *metric, uint32_t val,
  pr_table_t *labels);

/* Returns the collected samples for this metric and type. */
const array_header *prom_metric_get(pool *p, struct prom_metric *metric,
  int metric_type);
#define PROM_METRIC_TYPE_COUNTER	1
#define PROM_METRIC_TYPE_GAUGE		2
#define PROM_METRIC_TYPE_HISTOGRAM	3

/* Get the Prometheus exposition formatted text for the metric. */
const char *prom_metric_get_text(pool *p, struct prom_metric *metric,
  const char *registry_name, size_t *textlen);

struct prom_dbh *prom_metric_init(pool *p, const char *tables_path);
int prom_metric_free(pool *p, struct prom_dbh *dbh);

#endif /* MOD_PROMETHEUS_METRIC_H */
