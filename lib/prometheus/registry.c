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
#include "prometheus/text.h"

struct prom_registry {
  pool *pool;
  const char *name;
  pr_table_t *metrics;

  /* Pool/list of sorted metric names, for scraping. */
  pool *sorted_pool;
  array_header *sorted_keys;
};

static const char *trace_channel = "prometheus.registry";

int prom_registry_add_metric(struct prom_registry *registry,
    struct prom_metric *metric) {
  int res;

  if (registry == NULL ||
      metric == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_table_add(registry->metrics, prom_metric_get_name(metric),
    metric, sizeof(void *));
  return res;
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
  pool *tmp_pool;
  register unsigned int i;
  struct prom_text *text;
  int key_count;
  array_header *keys;
  char **elts, *str;

  if (p == NULL ||
      registry == NULL) {
    errno = EINVAL;
    return NULL;
  }

  /* Sanity check. */
  key_count = pr_table_count(registry->metrics);
  if (key_count == 0) {
    pr_trace_msg(trace_channel, 17,
      "'%s' registry has no metrics, returning no text", registry->name);
    errno = ENOENT;
    return NULL;
  }

  tmp_pool = make_sub_pool(p);
  text = prom_text_create(tmp_pool);

  if (registry->sorted_keys != NULL) {
    keys = registry->sorted_keys;

  } else {
   const void *key;

   keys = make_array(tmp_pool, key_count, sizeof(char *));

   pr_table_rewind(registry->metrics);
   key = pr_table_next(registry->metrics);
    while (key != NULL) {
      pr_signals_handle();

      /* No need to duplicate this text; it's a pointer to an object we
       * already have in memory.
       */
      *((char **) push_array(keys)) = (char *) key;
      key = pr_table_next(registry->metrics);
    }
  }

  elts = keys->elts;
  for (i = 0; i < keys->nelts; i++) {
    pool *iter_pool;
    struct prom_metric *metric;
    const char *metric_text;
    size_t metric_textlen;

    pr_trace_msg(trace_channel, 19, "getting text for '%s' metric", elts[i]);
    metric = (struct prom_metric *) pr_table_get(registry->metrics, elts[i],
      NULL);

    iter_pool = make_sub_pool(tmp_pool);
    metric_text = prom_metric_get_text(iter_pool, metric, registry->name,
      &metric_textlen);
    if (metric_text != NULL) {
      prom_text_add_str(text, pstrdup(tmp_pool, metric_text), metric_textlen);

    } else {
      pr_trace_msg(trace_channel, 7, "error getting '%s' metric text: %s",
        elts[i], strerror(errno));
    }

    destroy_pool(iter_pool);
  }

  prom_text_add_byte(text, '\n');
  str = prom_text_get_str(p, text, NULL);

  prom_text_destroy(text);
  destroy_pool(tmp_pool);
  return str;
}

static int metric_set_dbh_cb(const void *key_data, size_t key_datasz,
    const void *value_data, size_t value_datasz, void *user_data) {
  int res;
  struct prom_metric *metric;
  struct prom_dbh *dbh;

  metric = (struct prom_metric *) value_data;
  dbh = user_data;

  res = prom_metric_set_dbh(metric, dbh);
  if (res < 0) {
    pr_trace_msg(trace_channel, 7, "error setting metric dbh: %s",
      strerror(errno));
  }

  return 0;
}

int prom_registry_set_dbh(struct prom_registry *registry,
    struct prom_dbh *dbh) {
  int res, xerrno;

  if (registry == NULL ||
      dbh == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = pr_table_do(registry->metrics, metric_set_dbh_cb, dbh,
    PR_TABLE_DO_FL_ALL);
  xerrno = errno;
  if (res < 0) {
    pr_trace_msg(trace_channel, 3, "error doing registry metrics table: %s",
      strerror(xerrno));
  }

  errno = xerrno;
  return res;
}

static int metric_keycmp(const void *a, const void *b) {
  return strcmp(*((char **) a), *((char **) b));
}

int prom_registry_sort_metrics(struct prom_registry *registry) {
  int key_count;
  pool *sorted_pool;
  array_header *sorted_keys;
  const void *key;

  if (registry == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Discard any existing sorted list. */
  if (registry->sorted_pool != NULL) {
    destroy_pool(registry->sorted_pool);
    registry->sorted_pool = NULL;
    registry->sorted_keys = NULL;
  }

  /* If there are no metrics, there's nothing to do. */
  key_count = pr_table_count(registry->metrics);
  if (key_count == 0) {
    return 0;
  }

  sorted_pool = make_sub_pool(registry->pool);
  pr_pool_tag(sorted_pool, "Prometheus Registry sorted metric names");
  registry->sorted_pool = sorted_pool;

  sorted_keys = make_array(sorted_pool, key_count, sizeof(char *));

  pr_table_rewind(registry->metrics);
  key = pr_table_next(registry->metrics);
  while (key != NULL) {
    pr_signals_handle();

    /* No need to duplicate this text; it's a pointer to an object we
     * already have in memory.
     */
    *((char **) push_array(sorted_keys)) = (char *) key;
    key = pr_table_next(registry->metrics);
  }

  qsort((void *) sorted_keys->elts, sorted_keys->nelts, sizeof(char *),
    metric_keycmp);
  registry->sorted_keys = sorted_keys;

  if (pr_trace_get_level(trace_channel) > 17) {
    register unsigned int i;
    char **keys;

    pr_trace_msg(trace_channel, 17, "registry '%s' sorted metrics (%d):",
      registry->name, sorted_keys->nelts);
    keys = sorted_keys->elts;
    for (i = 0; i < sorted_keys->nelts; i++) {
      pr_trace_msg(trace_channel, 17, "  %s (%u)", keys[i], i+1);
    }
  }

  return 0;
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
