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

struct prom_histogram_bucket {
  int64_t bucket_id;
  int is_inf_bucket;
  double upper_bound;
  const char *upper_bound_text;
};

struct prom_metric {
  pool *pool;
  struct prom_dbh *dbh;
  const char *name;

  /* Counter */
  int64_t counter_id;
  const char *counter_name;
  size_t counter_namelen;
  const char *counter_help;
  size_t counter_helplen;

  /* Gauge */
  int64_t gauge_id;
  const char *gauge_name;
  size_t gauge_namelen;
  const char *gauge_help;
  size_t gauge_helplen;

  /* Histogram */
  const char *histogram_name;
  size_t histogram_namelen;
  const char *histogram_help;
  size_t histogram_helplen;
  unsigned int histogram_bucket_count;
  struct prom_histogram_bucket **histogram_buckets;
  const char *histogram_count_name;
  int64_t histogram_count_id;
  const char *histogram_sum_name;
  int64_t histogram_sum_id;
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

static struct prom_text *add_histogram_text(struct prom_text *text,
    const char *registry_name, size_t registry_namelen,
    const char *name, size_t namelen, const char *suffix, size_t suffixlen,
    const array_header *results) {
  register unsigned int i;
  char **elts;

  if (results->nelts == 0) {
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
    prom_text_add_str(text, name, namelen);
    prom_text_add_str(text, suffix, suffixlen);

    if (sample_labelslen > 0) {
      prom_text_add_str(text, sample_labels, sample_labelslen);
    }

    prom_text_add_byte(text, ' ');
    prom_text_add_str(text, sample_text, sample_textlen);
    prom_text_add_byte(text, '\n');
  }

  return text;
}

static struct prom_text *add_metric_type_text(pool *p,
    struct prom_metric *metric, struct prom_text *text,
    const char *registry_name, size_t registry_namelen, int metric_type) {
  register unsigned int i;
  const array_header *results, *histogram_counts = NULL, *histogram_sums = NULL;
  const char *type_name, *type_help;
  size_t type_namelen, type_helplen;
  char **elts;

  results = prom_metric_get(p, metric, metric_type, &histogram_counts,
    &histogram_sums);
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
      type_name = metric->histogram_name;
      type_namelen = metric->histogram_namelen;
      type_help = metric->histogram_help;
      type_helplen = metric->histogram_helplen;
      break;

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

    /* XXX For histogram buckets, ensure "+Inf" bucket is last. */
    if (metric_type == PROM_METRIC_TYPE_HISTOGRAM) {
      /* For histograms, `results` contains the bucket samples; name them
       * accordingly.
       */
      prom_text_add_str(text, "_bucket", 7);
    }

    if (sample_labelslen > 0) {
      prom_text_add_str(text, sample_labels, sample_labelslen);
    }

    prom_text_add_byte(text, ' ');
    prom_text_add_str(text, sample_text, sample_textlen);
    prom_text_add_byte(text, '\n');
  }

  if (metric_type == PROM_METRIC_TYPE_HISTOGRAM) {
    add_histogram_text(text, registry_name, registry_namelen, type_name,
      type_namelen, "_count", 6, histogram_counts);
    add_histogram_text(text, registry_name, registry_namelen, type_name,
      type_namelen, "_sum", 4, histogram_sums);
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
    int metric_type, const array_header **histogram_counts,
    const array_header **histogram_sums) {
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

    case PROM_METRIC_TYPE_HISTOGRAM: {
      register unsigned int i;
      const array_header *sample_results;

      if (metric->histogram_name == NULL) {
        /* No histogram associated with this metric. */
        errno = EPERM;
        return NULL;
      }

      /* For histograms, the caller needs to provide ways to return the
       * count/sum as well.
       */
      if (histogram_counts == NULL ||
          histogram_sums == NULL) {
        errno = EINVAL;
        return NULL;
      }

      for (i = 0; i < metric->histogram_bucket_count; i++) {
        struct prom_histogram_bucket *bucket;
        const array_header *bucket_results;

        bucket = ((struct prom_histogram_bucket **) metric->histogram_buckets)[i];
        bucket_results = prom_metric_db_sample_get(p, metric->dbh,
          bucket->bucket_id);
        if (bucket_results != NULL) {
          pr_trace_msg(trace_channel, 17,
            "found samples (%d) for histogram bucket '%s' metric '%s'",
            bucket_results->nelts/2, bucket->upper_bound_text,
            metric->histogram_name);
        }

        if (results != NULL) {
          array_cat((array_header *) results, bucket_results);

        } else {
          results = bucket_results;
        }
      }

      sample_results = prom_metric_db_sample_get(p, metric->dbh,
        metric->histogram_count_id);
      if (sample_results != NULL) {
        pr_trace_msg(trace_channel, 17,
          "found samples (%d) for histogram bucket 'count' metric '%s'",
          sample_results->nelts/2, metric->histogram_name);
      }
      *histogram_counts = sample_results;

      sample_results = prom_metric_db_sample_get(p, metric->dbh,
        metric->histogram_sum_id);
      if (sample_results != NULL) {
        pr_trace_msg(trace_channel, 17,
          "found samples (%d) for histogram bucket 'sum' metric '%s'",
          sample_results->nelts/2, metric->histogram_name);
      }
      *histogram_sums = sample_results;

      return results;
    }

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

int prom_metric_incr_type(pool *p, const struct prom_metric *metric,
    uint32_t val, pr_table_t *labels, int metric_type) {
  int res = 0, xerrno;
  pool *tmp_pool;
  struct prom_text *text;
  const char *metric_name, *label_str;
  int64_t metric_id;

  if (p == NULL ||
      metric == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Increment operation only supported for counters/gauges. */
  switch (metric_type) {
    case PROM_METRIC_TYPE_COUNTER:
      if (metric->counter_name == NULL) {
        errno = EPERM;
        return -1;
      }
      metric_name = metric->counter_name;
      metric_id = metric->counter_id;
      break;

    case PROM_METRIC_TYPE_GAUGE:
      if (metric->gauge_name == NULL) {
        errno = EPERM;
        return -1;
      }
      metric_name = metric->gauge_name;
      metric_id = metric->gauge_id;
      break;

    case PROM_METRIC_TYPE_HISTOGRAM:
      errno = EPERM;
      return -1;

    default:
      errno = EINVAL;
      return -1;
  }

  tmp_pool = make_sub_pool(p);
  text = prom_text_create(tmp_pool);
  label_str = prom_text_from_labels(tmp_pool, text, labels);

  res = prom_metric_db_sample_incr(p, metric->dbh, metric_id, (double) val,
    label_str);
  xerrno = errno;

  if (res < 0) {
   pr_trace_msg(trace_channel, 12, "error incrementing '%s' by %lu: %s",
      metric_name, (unsigned long) val, strerror(xerrno));
  }

  prom_text_destroy(text);
  destroy_pool(tmp_pool);
  errno = xerrno;
  return res;
}

int prom_metric_incr(pool *p, const struct prom_metric *metric, uint32_t val,
    pr_table_t *labels) {

  if (metric == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Increment operation only supported for counters/gauges. */
  if (metric->counter_name == NULL &&
      metric->gauge_name == NULL) {
    errno = EPERM;
    return -1;
  }

  if (metric->counter_name != NULL) {
    int res;

    res = prom_metric_incr_type(p, metric, val, labels,
      PROM_METRIC_TYPE_COUNTER);
    if (res < 0) {
      return -1;
    }
  }

  if (metric->gauge_name != NULL) {
    int res;

    res = prom_metric_incr_type(p, metric, val, labels, PROM_METRIC_TYPE_GAUGE);
    if (res < 0) {
      return -1;
    }
  }

  return 0;
}

int prom_metric_observe(pool *p, const struct prom_metric *metric, double val,
    pr_table_t *labels) {
  register int i;
  int res;
  pool *tmp_pool;
  struct prom_text *text;
  const char *label_str;

  if (p == NULL ||
      metric == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Observe operation only supported for histograms. */
  if (metric->histogram_name == NULL) {
    errno = EPERM;
    return -1;
  }

  tmp_pool = make_sub_pool(p);

  /* We start with the largest bucket, and work our way down. */
  for (i = metric->histogram_bucket_count-1; i >= 0; i--) {
    struct prom_histogram_bucket *bucket;

    bucket = ((struct prom_histogram_bucket **) metric->histogram_buckets)[i];
    if (val > bucket->upper_bound &&
        bucket->is_inf_bucket == FALSE) {
      /* Value is too large for this bucket. */
      break;
    }

    (void) pr_table_add(labels, "le", bucket->upper_bound_text, 0);
    text = prom_text_create(tmp_pool);
    label_str = prom_text_from_labels(tmp_pool, text, labels);

    res = prom_metric_db_sample_incr(p, metric->dbh, bucket->bucket_id,
      (double) 1.0, label_str);
    if (res < 0) {
      pr_trace_msg(trace_channel, 12, "error observing '%s' with %g: %s",
        metric->histogram_name, val, strerror(errno));
    }

    prom_text_destroy(text);
    (void) pr_table_remove(labels, "le", NULL);
  }

  text = prom_text_create(tmp_pool);
  label_str = prom_text_from_labels(tmp_pool, text, labels);

  res = prom_metric_db_sample_incr(p, metric->dbh, metric->histogram_count_id,
    (double) 1.0, label_str);
  if (res < 0) {
    pr_trace_msg(trace_channel, 12, "error incrementing '%s' by %lu: %s",
      metric->histogram_count_name, (unsigned long) val, strerror(errno));
  }

  res = prom_metric_db_sample_incr(p, metric->dbh, metric->histogram_sum_id,
    val, label_str);
  if (res < 0) {
    pr_trace_msg(trace_channel, 12, "error incrementing '%s' by %lu: %s",
      metric->histogram_sum_name, (unsigned long) val, strerror(errno));
  }

  prom_text_destroy(text);
  destroy_pool(tmp_pool);

  return 0;
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
  pr_trace_msg(trace_channel, 27,
    "added '%s' counter metric (ID %lld) to database", metric->counter_name,
    (long long int) metric->counter_id);
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
  pr_trace_msg(trace_channel, 27,
    "added '%s' gauge metric (ID %lld) to database", metric->gauge_name,
    (long long int) metric->gauge_id);
  return 0;
}

static const char *get_double_text(pool *p, double val) {
  char *text;
  size_t text_len;

  text_len = 50;
  text = pcalloc(p, text_len);
  snprintf(text, text_len-1, "%f", val);

  if (strstr(text, ".") == NULL) {
    strcat(text, ".0");
  }

  return text;
}

int prom_metric_add_histogram(struct prom_metric *metric, const char *suffix,
    const char *help_text, unsigned int bucket_count, ...) {
  register unsigned int i;
  int res, xerrno, have_error = FALSE;
  va_list ap;

  if (metric == NULL ||
      help_text == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (suffix != NULL) {
    metric->histogram_name = pstrcat(metric->pool, metric->name, "_", suffix,
      NULL);

  } else {
    metric->histogram_name = metric->name;
  }

  metric->histogram_namelen = strlen(metric->histogram_name);
  metric->histogram_help = pstrdup(metric->pool, help_text);
  metric->histogram_helplen = strlen(metric->histogram_help);

  /* Add one more for the "+Inf" bucket. */
  metric->histogram_bucket_count = bucket_count + 1;
  metric->histogram_buckets = pcalloc(metric->pool,
    sizeof(struct prom_histogram_bucket *) * metric->histogram_bucket_count);
  for (i = 0; i < metric->histogram_bucket_count; i++) {
    metric->histogram_buckets[i] = pcalloc(metric->pool,
      sizeof(struct prom_histogram_bucket));
  }

  va_start(ap, bucket_count);
  for (i = 0; i < metric->histogram_bucket_count; i++) {
    struct prom_histogram_bucket *bucket;
    const char *sample_name;

    bucket = ((struct prom_histogram_bucket **) metric->histogram_buckets)[i];

    if (i != metric->histogram_bucket_count-1) {
      bucket->upper_bound = va_arg(ap, double);
      bucket->upper_bound_text = get_double_text(metric->pool,
        bucket->upper_bound);
      sample_name = pstrcat(metric->pool, metric->histogram_name, "_",
        bucket->upper_bound_text, NULL);

    } else {
      /* The "+Inf" bucket. */
      bucket->is_inf_bucket = TRUE;
      bucket->upper_bound_text = pstrdup(metric->pool, "+Inf");
      sample_name = pstrcat(metric->pool, metric->histogram_name, "_inf", NULL);
    }

    res = prom_metric_db_exists(metric->pool, metric->dbh, sample_name);
    if (res == 0) {
      pr_trace_msg(trace_channel, 3, "'%s' metric already exists in database",
        sample_name);
      xerrno = EEXIST;
      have_error = TRUE;
      break;
    }

    res = prom_metric_db_create(metric->pool, metric->dbh,
      sample_name, PROM_METRIC_TYPE_HISTOGRAM, &(bucket->bucket_id));
    if (res < 0) {
      pr_trace_msg(trace_channel, 3, "error adding '%s' metric to database: %s",
        sample_name, strerror(errno));
      xerrno = EEXIST;
      have_error = TRUE;
      break;
    }
  }
  va_end(ap);

  if (have_error == TRUE) {
    errno = xerrno;
    return -1;
  }

  /* The histogram "count" sample. */
  metric->histogram_count_name = pstrcat(metric->pool, metric->histogram_name,
    "_count", NULL);
  res = prom_metric_db_exists(metric->pool, metric->dbh,
    metric->histogram_count_name);
  if (res == 0) {
    pr_trace_msg(trace_channel, 3, "'%s' metric already exists in database",
      metric->histogram_count_name);
    errno = EEXIST;
    return -1;
  }

  res = prom_metric_db_create(metric->pool, metric->dbh,
    metric->histogram_count_name, PROM_METRIC_TYPE_HISTOGRAM,
    &(metric->histogram_count_id));
  if (res < 0) {
    pr_trace_msg(trace_channel, 3, "error adding '%s' metric to database: %s",
      metric->histogram_count_name, strerror(errno));
    errno = EEXIST;
    return -1;
  }

  /* The histogram "sum" sample. */
  metric->histogram_sum_name = pstrcat(metric->pool, metric->histogram_name,
    "_sum", NULL);
  res = prom_metric_db_exists(metric->pool, metric->dbh,
    metric->histogram_sum_name);
  if (res == 0) {
    pr_trace_msg(trace_channel, 3, "'%s' metric already exists in database",
      metric->histogram_sum_name);
    errno = EEXIST;
    return -1;
  }

  res = prom_metric_db_create(metric->pool, metric->dbh,
    metric->histogram_sum_name, PROM_METRIC_TYPE_HISTOGRAM,
    &(metric->histogram_sum_id));
  if (res < 0) {
    pr_trace_msg(trace_channel, 3, "error adding '%s' metric to database: %s",
      metric->histogram_sum_name, strerror(errno));
    errno = EEXIST;
    return -1;
  }

  pr_trace_msg(trace_channel, 27,
    "added '%s' histogram metric (count ID %lld, sum ID %lld) to database",
    metric->histogram_name, (long long) metric->histogram_count_id,
    (long long) metric->histogram_sum_id);
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
