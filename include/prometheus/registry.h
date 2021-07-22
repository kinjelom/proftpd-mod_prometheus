/*
 * ProFTPD - mod_prometheus registry API
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

#ifndef MOD_PROMETHEUS_REGISTRY_H
#define MOD_PROMETHEUS_REGISTRY_H

#include "mod_prometheus.h"
#include "prometheus/db.h"
#include "prometheus/metric.h"

struct prom_registry;

/* Returns the name/prefix prepended to all metrics in this registry. */
const char *prom_registry_get_name(struct prom_registry *registry);

/* Returns the text for all collector's metrics in the registry. */
const char *prom_registry_get_text(pool *p, struct prom_registry *registry);

int prom_registry_add_metric(struct prom_registry *registry,
  struct prom_metric *metric);
int prom_registry_remove_metric(struct prom_registry *registry,
  struct prom_metric *metric);

/* Returns the metric object for the given metric name. */
const struct prom_metric *prom_registry_get_metric(
  struct prom_registry *registry, const char *metric_name);

/* Sets the given database handle on all registered metrics. */
int prom_registry_set_dbh(struct prom_registry *registry, struct prom_dbh *dbh);

/* Caches a sorted list of metric names, for use in generating the text. */
int prom_registry_sort_metrics(pool *p, struct prom_registry *registry);

struct prom_registry *prom_registry_init(pool *p, const char *name);
int prom_registry_free(struct prom_registry *registry);

#endif /* MOD_PROMETHEUS_REGISTRY_H */
