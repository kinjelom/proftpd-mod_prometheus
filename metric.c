/*
 * ProFTPD - mod_prometheus metric implementation
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
#include "metric.h"

struct prom_metric {
  pool *pool;
  const char *name;

  /* XXX Associated counter, gauge, histogram, if present */
};

static const char *trace_channel = "prometheus.metric";

/* Returns the name of the given metric. */
const char *prom_metric_get_name(struct prom_metric *metric) {
  if (metric == NULL) {
    errno = EINVAL;
    return NULL;
  }

  return metric->name;
}

/* Returns the text for the given metric. */
const char *prom_metric_get_text(pool *p, struct prom_metric *metric) {
  if (p == NULL ||
      metric == NULL) {
    errno = EINVAL;
    return NULL;
  }

  errno = ENOSYS;
  return NULL;
}

/* Increment the specified metric ID. */
int prom_metric_incr_value(pool *p, struct prom_metric *metric,
    int32_t incr, pr_table_t *labels) {
  if (p == NULL ||
      metric == NULL) {
    errno = EINVAL;
    return -1;
  }

  errno = ENOSYS;
  return -1;
}

struct prom_metric *prom_metric_create(pool *p, const char *name) {
  pool *metric_pool;
  struct prom_metric *metric;

  if (p == NULL ||
      name == NULL) {
    errno = EINVAL;
    return NULL;
  }

  metric_pool = make_sub_pool(p);
  pr_pool_tag(metric_pool, "Prometheus metric pool");

  metric = pcalloc(metric_pool, sizeof(struct prom_metric));
  metric->pool = metric_pool;
  metric->name = pstrdup(metric->pool, name);

/* XXX Insert a row in the db for this new metric -- if it doesn't already
 * exist? -- and associate the metric_id to the handle, too!
 *
 * To do this, we add the metric to the registry, which will add the
 * registry dbh to the metric.  THEN we can use the dbh to add ourselves
 * to the db.  Or not.  It's an incestuous tangle, registry/dbh/metric.
 */

  return metric;
}

int prom_metric_destroy(pool *p, struct prom_metric *metric) {
  if (metric == NULL) {
    errno = EINVAL;
    return -1;
  }

  destroy_pool(metric->pool);
  return 0;
}

int prom_metric_init(pool *p, const char *tables_path,
    struct prom_registry *registry) {

  /* XXX Automatically instantiates metrics objects for all known metric
   * names.
   * Registers them in the given registry.
   */

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

  errno = ENOSYS;
  return -1;
}

int prom_metric_free(pool *p) {
  return 0;
}
