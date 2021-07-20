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
#include "prometheus/metric.h"
#include "prometheus/metric/db.h"

struct prom_metric {
  pool *pool;
  struct prom_dbh *dbh;
  const char *name;

  const char *counter_name;
  int64_t counter_id;

  const char *gauge_name;
  int64_t gauge_id;
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

int prom_metric_decr(const struct prom_metric *metric, uint32_t decr,
    pr_table_t *labels) {
  if (metric == NULL) {
    errno = EINVAL;
    return -1;
  }

  errno = ENOSYS;
  return -1;
}

int prom_metric_incr(const struct prom_metric *metric, uint32_t incr,
    pr_table_t *labels) {
  if (metric == NULL) {
    errno = EINVAL;
    return -1;
  }

  errno = ENOSYS;
  return -1;
}

int prom_metric_set(const struct prom_metric *metric, uint32_t val,
    pr_table_t *labels) {
  if (metric == NULL) {
    errno = EINVAL;
    return -1;
  }

  errno = ENOSYS;
  return -1;
}

int prom_metric_add_counter(struct prom_metric *metric, const char *suffix,
    const char *help_text) {
  int res;
  int64_t counter_id;

  if (metric == NULL ||
      help_text == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (suffix != NULL) {
    metric->counter_name = pstrcat(metric->pool, metric->name, "_", suffix,
      NULL);

  } else {
    metric->counter_name = metric->name;
  }

  res = prom_metric_db_exists(metric->pool, metric->dbh, metric->counter_name);
  if (res == 0) {
    pr_trace_msg(trace_channel, 3, "'%s' metric already exists in database",
      metric->counter_name);
    errno = EEXIST;
    return -1;
  }

  res = prom_metric_db_create(metric->pool, metric->dbh, metric->counter_name,
    PROM_METRIC_TYPE_COUNTER, &counter_id);
  if (res < 0) {
    pr_trace_msg(trace_channel, 3, "error adding '%s' metric to database: %s",
      metric->counter_name, strerror(errno));
    errno = EEXIST;
    return -1;
  }

  metric->counter_id = counter_id;
  return 0;
}

int prom_metric_add_gauge(struct prom_metric *metric, const char *suffix,
    const char *help_text) {
  int res;
  int64_t gauge_id;

  if (metric == NULL ||
      help_text == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (suffix != NULL) {
    metric->gauge_name = pstrcat(metric->pool, metric->name, "_", suffix,
      NULL);

  } else {
    metric->gauge_name = metric->name;
  }

  res = prom_metric_db_exists(metric->pool, metric->dbh, metric->gauge_name);
  if (res == 0) {
    pr_trace_msg(trace_channel, 3, "'%s' metric already exists in database",
      metric->gauge_name);
    errno = EEXIST;
    return -1;
  }

  res = prom_metric_db_create(metric->pool, metric->dbh, metric->gauge_name,
    PROM_METRIC_TYPE_GAUGE, &gauge_id);
  if (res < 0) {
    pr_trace_msg(trace_channel, 3, "error adding '%s' metric to database: %s",
      metric->gauge_name, strerror(errno));
    errno = EEXIST;
    return -1;
  }

  metric->gauge_id = gauge_id;
  return 0;
}

struct prom_metric *prom_metric_create(pool *p, const char *name,
    struct prom_dbh *dbh) {
  pool *metric_pool;
  struct prom_metric *metric;

  if (p == NULL ||
      name == NULL ||
      dbh == NULL) {
    errno = EINVAL;
    return NULL;
  }

  metric_pool = make_sub_pool(p);
  pr_pool_tag(metric_pool, "Prometheus metric pool");

  metric = pcalloc(metric_pool, sizeof(struct prom_metric));
  metric->pool = metric_pool;
  metric->name = pstrdup(metric->pool, name);
  metric->dbh = dbh;

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

struct prom_dbh *prom_metric_init(pool *p, const char *tables_path) {
  struct prom_dbh *dbh;

  dbh = prom_metric_db_init(p, tables_path, 0);
  if (dbh == NULL) {
    int xerrno = errno;

    (void) pr_log_pri(PR_LOG_NOTICE, MOD_PROMETHEUS_VERSION
      ": failed to initialize metrics datastore: %s", strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  return dbh;
}

int prom_metric_free(pool *p) {
  return 0;
}
