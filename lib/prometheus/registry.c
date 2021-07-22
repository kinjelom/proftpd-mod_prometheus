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
#include "prometheus/registry.h"
#include "prometheus/metric.h"

struct prom_registry {
  pool *pool;
  const char *name;
  pr_table_t *metrics;
};

static const char *trace_channel = "prometheus.registry";

int prom_registry_add_metric(struct prom_registry *registry,
    struct prom_metric *metric) {
  if (registry == NULL ||
      metric == NULL) {
    errno = EINVAL;
    return -1;
  }

  errno = ENOSYS;
  return -1;
}

const struct prom_metric *prom_registry_get_metric(
    struct prom_registry *registry, const char *metric_name) {
  if (registry == NULL ||
      metric_name == NULL) {
    errno = EINVAL;
    return NULL;
  }

  return pr_table_get(registry->metrics, metric_name, NULL);
}

const char *prom_registry_get_name(struct prom_registry *registry) {
  if (registry == NULL) {
    errno = EINVAL;
    return NULL;
  }

  return registry->name;
}

/* Returns the text for all metrics in the registry. */
const char *prom_registry_get_text(pool *p, struct prom_registry *registry) {
  const char *text;

  if (p == NULL ||
      registry == NULL) {
    errno = EINVAL;
    return NULL;
  }

  /* Notes:
   *
   * For each metric (sorted order!):
   *   get metric text (registry->registry_name, text)
   *     ignore metrics w/o text (no counter/gauge/histogram; code bug!)
   */

  text = pstrcat(p, "OK\n\n", NULL);
  return text;
}

/* XXX Once all metrics have been created, registered, call
 * prom_registry_sort_metrics().
 *
 * Why?  We ideally want to return all metrics in sorted order, every time
 * we are scraped.  So doing a one-time ordering of the list/keys is best.
 * Plus it will help with lookups.
 *
 * Since we're dealing with a table, maybe it's easiest to get the keys,
 * sort them, and cache the sorted key list in the registry handle?
 */
int prom_registry_sort_metrics(pool *p, struct prom_registry *registry) {
  if (p == NULL ||
      registry == NULL) {
    errno = EINVAL;
    return -1;
  }

  errno = ENOSYS;
  return -1;
}

struct prom_registry *prom_registry_init(pool *p, const char *name) {
  struct prom_registry *registry;
  pool *registry_pool;

  if (p == NULL ||
      name == NULL) {
    errno = EINVAL;
    return NULL;
  }

  registry_pool = make_sub_pool(p);
  pr_pool_tag(registry_pool, "Prometheus Registry pool");

  registry = pcalloc(registry_pool, sizeof(struct prom_registry));
  registry->pool = registry_pool;
  registry->name = pstrdup(registry->pool, name);
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
