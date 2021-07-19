/*
 * ProFTPD - mod_prometheus registry implementation
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

#include "mod_prometheus.h"
#include "registry.h"
#include "metric.h"

struct prom_registry {
  pool *pool;
  pr_table_t *metrics;
};

static const char *trace_channel = "prometheus.registry";

const void *prom_registry_get_metric(struct prom_registry *registry,
    const char *metric_name) {
  if (registry == NULL ||
      metric_name == NULL) {
    errno = EINVAL;
    return NULL;
  }

  return pr_table_get(registry->metrics, metric_name, NULL);
}

/* Returns the text for all metrics in the registry. */
const char *prom_registry_get_text(pool *p, struct prom_registry *registry) {
  if (p == NULL ||
      registry == NULL) {
    errno = EINVAL;
    return NULL;
  }

  errno = ENOSYS;
  return NULL;
}

struct prom_registry *prom_registry_init(pool *p) {
  struct prom_registry *registry;
  pool *registry_pool;

  if (p == NULL) {
    errno = EINVAL;
    return NULL;
  }

  registry_pool = make_sub_pool(p);
  pr_pool_tag(registry_pool, "Prometheus Registry pool");

  registry = pcalloc(registry_pool, sizeof(struct prom_registry));
  registry->pool = registry_pool;
  registry->metrics = pr_table_nalloc(registry->pool, 0, 8);

  return registry;
}

static int metric_free_cb(const void *key_data, size_t key_datasz,
    const void *value_data, size_t value_datasz, void *user_data) {
  int res;
  struct prom_metric *metric;
  pool *registry_pool;

  metric = (struct prom_metric *) value_data;
  registry_pool = user_data;

  res = prom_metric_destroy(registry_pool, metric);
  if (res < 0) {
    pr_trace_msg(trace_channel, 7, "error destroy metric: %s",
      strerror(errno));
  }

  return 0;
}

int prom_registry_free(struct prom_registry *registry) {
  int res;

  if (registry == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_table_do(registry->metrics, metric_free_cb, registry->pool,
    PR_TABLE_DO_FL_ALL);
  if (res < 0) {
    pr_trace_msg(trace_channel, 3, "error doing registry metrics table: %s",
      strerror(errno));
  }

  (void) pr_table_empty(registry->metrics);
  (void) pr_table_free(registry->metrics);
  destroy_pool(registry->pool);

  return 0;
}
