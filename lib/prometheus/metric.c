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
#include "prometheus/text.h"

struct prom_metric {
  pool *pool;
  struct prom_dbh *dbh;
  const char *name;

  int64_t counter_id;
  const char *counter_name;
  size_t counter_namelen;
  const char *counter_help;
  size_t counter_helplen;

  int64_t gauge_id;
  const char *gauge_name;
  size_t gauge_namelen;
  const char *gauge_help;
  size_t gauge_helplen;

  int64_t histogram_id;
  const char *histogram_name;
  size_t histogram_namelen;
  const char *histogram_help;
  size_t histogram_helplen;
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

static struct prom_text *add_help_text(struct prom_text *text,
    const char *registry_name, size_t registry_namelen,
    const char *name, size_t namelen, const char *help, size_t helplen) {

  prom_text_add_str(text, "# HELP ", 7);
  prom_text_add_str(text, registry_name, registry_namelen);
  prom_text_add_byte(text, '_');
  prom_text_add_str(text, name, namelen);
  prom_text_add_byte(text, ' ');
  prom_text_add_str(text, help, helplen);
  prom_text_add_str(text, ".\n", 2);

  return text;
}

static struct prom_text *add_type_text(struct prom_text *text,
    const char *registry_name, size_t registry_namelen,
    const char *name, size_t namelen, int metric_type) {

  prom_text_add_str(text, "# TYPE ", 7);
  prom_text_add_str(text, registry_name, registry_namelen);
  prom_text_add_byte(text, '_');
  prom_text_add_str(text, name, namelen);

  switch (metric_type) {
    case PROM_METRIC_TYPE_COUNTER:
      prom_text_add_str(text, " counter\n", 9);
      break;

    case PROM_METRIC_TYPE_GAUGE:
      prom_text_add_str(text, " gauge\n", 7);
      break;

    case PROM_METRIC_TYPE_HISTOGRAM:
      prom_text_add_str(text, " histogram\n", 11);
      break;

    default:
      break;
  }

  return text;
}

static struct prom_text *add_metric_type_text(pool *p,
    struct prom_metric *metric, struct prom_text *text,
    const char *registry_name, size_t registry_namelen, int metric_type) {
  register unsigned int i;
  const array_header *results;
  const char *type_name, *type_help;
  size_t type_namelen, type_helplen;
  char **elts;

  results = prom_metric_get(p, metric, metric_type);
  if (results == NULL) {
    return NULL;
  }

  switch (metric_type) {
    case PROM_METRIC_TYPE_COUNTER:
      type_name = metric->counter_name;
      type_namelen = metric->counter_namelen;
      type_help = metric->counter_help;
      type_helplen = metric->counter_helplen;
      break;

    case PROM_METRIC_TYPE_GAUGE:
      type_name = metric->gauge_name;
      type_namelen = metric->gauge_namelen;
      type_help = metric->gauge_help;
      type_helplen = metric->gauge_helplen;
      break;

    case PROM_METRIC_TYPE_HISTOGRAM:
      errno = ENOSYS;
      return NULL;

    default:
      errno = EINVAL;
      return NULL;
  }

  add_help_text(text, registry_name, registry_namelen, type_name, type_namelen,
    type_help, type_helplen);
  add_type_text(text, registry_name, registry_namelen, type_name, type_namelen,
    metric_type);

  if (results->nelts == 0) {
    /* Provide the default value of 0. */
    prom_text_add_str(text, registry_name, registry_namelen);
    prom_text_add_byte(text, '_');
    prom_text_add_str(text, type_name, type_namelen);

    /* TODO: What's the default for a histogram? */
    prom_text_add_str(text, " 0\n", 3);

    return text;
  }

  elts = results->elts;
  for (i = 0; i < results->nelts; i += 2) {
    double sample_val;
    char sample_text[50], *sample_labels, *ptr = NULL;
    size_t sample_labelslen;
    int sample_textlen;

    sample_val = strtod(elts[i], &ptr);
    memset(sample_text, '\0', sizeof(sample_text));
    sample_textlen = snprintf(sample_text, sizeof(sample_text)-1, "%0.17g",
      sample_val);

    sample_labels = elts[i+1];
    sample_labelslen = strlen(sample_labels);

    prom_text_add_str(text, registry_name, registry_namelen);
    prom_text_add_byte(text, '_');
    prom_text_add_str(text, type_name, type_namelen);

    if (sample_labelslen > 0) {
      prom_text_add_str(text, sample_labels, sample_labelslen);
    }

    prom_text_add_byte(text, ' ');
    prom_text_add_str(text, sample_text, sample_textlen);
    prom_text_add_byte(text, '\n');
  }

  return text;
}

/* Get the Prometheus text for the given metric: for each metric
 * type, add:
 *
 *  "# HELP name ...\n"
 *  "# TYPE name ...\n"
 *  "name<sample_labels> sample_val\n"
 */
const char *prom_metric_get_text(pool *p, struct prom_metric *metric,
    const char *registry_name, size_t *len) {
  int xerrno;
  pool *tmp_pool;
  size_t registry_namelen;
  struct prom_text *text;
  char *res;

  if (p == NULL ||
      metric == NULL ||
      registry_name == NULL ||
      len == NULL) {
    errno = EINVAL;
    return NULL;
  }

  registry_namelen = strlen(registry_name);
  tmp_pool = make_sub_pool(p);
  text = prom_text_create(tmp_pool);

  add_metric_type_text(tmp_pool, metric, text, registry_name, registry_namelen,
    PROM_METRIC_TYPE_COUNTER);
  add_metric_type_text(tmp_pool, metric, text, registry_name, registry_namelen,
    PROM_METRIC_TYPE_GAUGE);
  add_metric_type_text(tmp_pool, metric, text, registry_name, registry_namelen,
    PROM_METRIC_TYPE_HISTOGRAM);

  res = prom_text_get_str(p, text, len);
  xerrno = errno;

  if (res != NULL) {
    pr_trace_msg(trace_channel, 19, "converted '%s' metric to text:\n%.*s",
      metric->name, (int) *len, res);
  }

  prom_text_destroy(text);
  destroy_pool(tmp_pool);

  errno = xerrno;
  return res;
}

/* Returns the samples collected for this metric and type. */
const array_header *prom_metric_get(pool *p, struct prom_metric *metric,
    int metric_type) {
  const array_header *results = NULL;

  if (p == NULL ||
      metric == NULL) {
    errno = EINVAL;
    return NULL;
  }

  switch (metric_type) {
    case PROM_METRIC_TYPE_COUNTER:
      if (metric->counter_name == NULL) {
        /* No counter associated with this metric. */
        errno = EPERM;
        return NULL;
      }

      results = prom_metric_db_sample_get(p, metric->dbh, metric->counter_id);
      if (results != NULL) {
        pr_trace_msg(trace_channel, 17,
          "found samples (%d) for counter metric '%s'", results->nelts/2,
          metric->counter_name);
      }
      break;

    case PROM_METRIC_TYPE_GAUGE:
      if (metric->gauge_name == NULL) {
        /* No gauge associated with this metric. */
        errno = EPERM;
        return NULL;
      }

      results = prom_metric_db_sample_get(p, metric->dbh, metric->gauge_id);
      if (results != NULL) {
        pr_trace_msg(trace_channel, 17,
          "found samples (%d) for gauge metric '%s'", results->nelts/2,
          metric->gauge_name);
      }
      break;

    case PROM_METRIC_TYPE_HISTOGRAM:
      /* Not yet implemented. */
      errno = ENOSYS;
      return NULL;

    default:
      pr_trace_msg(trace_channel, 9,
        "unknown metric type %d requested for '%s'", metric_type, metric->name);
      errno = EINVAL;
      return NULL;
  }

  return results;
}

int prom_metric_decr(pool *p, const struct prom_metric *metric, uint32_t val,
    pr_table_t *labels) {
  int res, xerrno;
  pool *tmp_pool;
  struct prom_text *text;
  const char *label_str;

  if (p == NULL ||
      metric == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Decrement operation only supported for gauges. */
  if (metric->gauge_name == NULL) {
    errno = EPERM;
    return -1;
  }

  tmp_pool = make_sub_pool(p);
  text = prom_text_create(tmp_pool);
  label_str = prom_text_from_labels(tmp_pool, text, labels);
  res = prom_metric_db_sample_decr(p, metric->dbh, metric->gauge_id,
    (double) val, label_str);
  xerrno = errno;

  prom_text_destroy(text);
  destroy_pool(tmp_pool);
  errno = xerrno;
  return res;
}

int prom_metric_incr(pool *p, const struct prom_metric *metric, uint32_t val,
    pr_table_t *labels) {
  int res = 0, xerrno;
  pool *tmp_pool;
  struct prom_text *text;
  const char *label_str;

  if (p == NULL ||
      metric == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Increment operation only supported for counters/gauges. */
  if (metric->counter_name == NULL &&
      metric->gauge_name == NULL) {
    errno = EPERM;
    return -1;
  }

  tmp_pool = make_sub_pool(p);
  text = prom_text_create(tmp_pool);
  label_str = prom_text_from_labels(tmp_pool, text, labels);

  if (metric->counter_name != NULL) {
    res = prom_metric_db_sample_incr(p, metric->dbh, metric->counter_id,
      (double) val, label_str);
    xerrno = errno;
  }

  if (res == 0 &&
      metric->gauge_name != NULL) {
    res = prom_metric_db_sample_incr(p, metric->dbh, metric->gauge_id,
      (double) val, label_str);
    xerrno = errno;
  }

  prom_text_destroy(text);
  destroy_pool(tmp_pool);
  errno = xerrno;
  return res;
}

int prom_metric_set(pool *p, const struct prom_metric *metric, uint32_t val,
    pr_table_t *labels) {
  int res, xerrno;
  pool *tmp_pool;
  struct prom_text *text;
  const char *label_str;

  if (p == NULL ||
      metric == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Set operation only supported for gauges. */
  if (metric->gauge_name == NULL) {
    errno = EPERM;
    return -1;
  }

  tmp_pool = make_sub_pool(p);
  text = prom_text_create(tmp_pool);
  label_str = prom_text_from_labels(tmp_pool, text, labels);
  res = prom_metric_db_sample_set(p, metric->dbh, metric->gauge_id,
    (double) val, label_str);
  xerrno = errno;

  prom_text_destroy(text);
  destroy_pool(tmp_pool);
  errno = xerrno;
  return res;
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

  metric->counter_namelen = strlen(metric->counter_name);
  metric->counter_help = pstrdup(metric->pool, help_text);
  metric->counter_helplen = strlen(metric->counter_help);

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

  metric->gauge_namelen = strlen(metric->gauge_name);
  metric->gauge_help = pstrdup(metric->pool, help_text);
  metric->gauge_helplen = strlen(metric->gauge_help);

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

int prom_metric_set_dbh(struct prom_metric *metric, struct prom_dbh *dbh) {
  if (metric == NULL ||
      dbh == NULL) {
    errno = EINVAL;
    return -1;
  }

  metric->dbh = dbh;
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

int prom_metric_free(pool *p, struct prom_dbh *dbh) {
  int res;

  res = prom_metric_db_close(p, dbh);
  return res;
}
