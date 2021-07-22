/*
 * ProFTPD - mod_prometheus metrics datastore implementation
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
#include "prometheus/db.h"
#include "prometheus/metric/db.h"

#define PROM_METRICS_DB_SCHEMA_NAME	"prom_metrics"
#define PROM_METRICS_DB_SCHEMA_VERSION	1

static const char *trace_channel = "prometheus.metric.db";

static int metrics_db_add_schema(pool *p, struct prom_dbh *dbh,
    const char *db_path) {
  int res;
  const char *stmt, *errstr = NULL;

  /* CREATE TABLE metrics (
   *   metric_id INTEGER NOT NULL PRIMARY KEY,
   *   metric_name TEXT NOT NULL,
   *   metric_type INTEGER NOT NULL
   * );
   */
  stmt = "CREATE TABLE IF NOT EXISTS metrics (metric_id INTEGER NOT NULL PRIMARY KEY, metric_name TEXT NOT NULL, metric_type INTEGER NOT NULL);";
  res = prom_db_exec_stmt(p, dbh, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(prometheus_logfd, MOD_PROMETHEUS_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  /* CREATE INDEX metric_id_idx */
  stmt = "CREATE INDEX IF NOT EXISTS metric_id_idx ON metrics (metric_id);";
  res = prom_db_exec_stmt(p, dbh, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(prometheus_logfd, MOD_PROMETHEUS_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  /* CREATE TABLE metric_samples (
   *   sample_id INTEGER NOT NULL PRIMARY KEY,
   *   metric_id INTEGER NOT NULL,
   *   sample_value DOUBLE NOT NULL,
   *   sample_labels TEXT NOT NULL,
   *   FOREIGN KEY (metric_id) REFERENCES metrics (metric_id)
   * );
   */
  stmt = "CREATE TABLE IF NOT EXISTS metric_samples (sample_id INTEGER NOT NULL PRIMARY KEY, metric_id INTEGER NOT NULL, sample_value DOUBLE NOT NULL, sample_labels TEXT NOT NULL, FOREIGN KEY (metric_id) REFERENCES metrics (metric_id));";
  res = prom_db_exec_stmt(p, dbh, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(prometheus_logfd, MOD_PROMETHEUS_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  /* CREATE INDEX sample_id_idx */
  stmt = "CREATE INDEX IF NOT EXISTS sample_id_idx ON metric_samples (sample_id);";
  res = prom_db_exec_stmt(p, dbh, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(prometheus_logfd, MOD_PROMETHEUS_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  return 0;
}

static int metrics_db_truncate_tables(pool *p, struct prom_dbh *dbh) {
  int res;
  const char *index_name, *stmt, *errstr = NULL;

  stmt = "DELETE FROM metric_samples;";
  res = prom_db_exec_stmt(p, dbh, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(prometheus_logfd, MOD_PROMETHEUS_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  stmt = "DELETE FROM metrics;";
  res = prom_db_exec_stmt(p, dbh, stmt, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(prometheus_logfd, MOD_PROMETHEUS_VERSION,
      "error executing '%s': %s", stmt, errstr);
    errno = EPERM;
    return -1;
  }

  /* Note: don't forget to rebuild the indices, too! */

  index_name = "sample_id_idx";
  res = prom_db_reindex(p, dbh, index_name, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(prometheus_logfd, MOD_PROMETHEUS_VERSION,
      "error reindexing '%s': %s", index_name, errstr);
    errno = EPERM;
    return -1;
  }

  index_name = "metric_id_idx";
  res = prom_db_reindex(p, dbh, index_name, &errstr);
  if (res < 0) {
    (void) pr_log_writefile(prometheus_logfd, MOD_PROMETHEUS_VERSION,
      "error reindexing '%s': %s", index_name, errstr);
    errno = EPERM;
    return -1;
  }

  return 0;
}

int prom_metric_db_create(pool *p, struct prom_dbh *dbh,
    const char *metric_name, int metric_type, int64_t *row_id) {
  int res, xerrno;
  const char *stmt, *errstr = NULL;
  array_header *results;

  if (p == NULL ||
      dbh == NULL ||
      metric_name == NULL) {
    errno = EINVAL;
    return -1;
  }

  stmt = "INSERT INTO metrics (metric_name, metric_type) VALUES (?, ?);";
  res = prom_db_prepare_stmt(p, dbh, stmt);
  if (res < 0) {
    return -1;
  }

  res = prom_db_bind_stmt(p, dbh, stmt, 1, PROM_DB_BIND_TYPE_TEXT,
    (void *) metric_name);
  if (res < 0) {
    return -1;
  }

  res = prom_db_bind_stmt(p, dbh, stmt, 2, PROM_DB_BIND_TYPE_INT,
    (void *) &metric_type);
  if (res < 0) {
    return -1;
  }

  results = prom_db_exec_prepared_stmt(p, dbh, stmt, &errstr);
  xerrno = errno;
  (void) prom_db_finish_stmt(p, dbh, stmt);

  if (results == NULL) {
    pr_trace_msg(trace_channel, 7,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));
    errno = EPERM;
    return -1;
  }

  if (row_id != NULL) {
    res = prom_db_last_row_id(p, dbh, row_id);
    if (res < 0) {
      pr_trace_msg(trace_channel, 7,
        "error obtaining last row ID for metric '%s', type %d: %s",
        metric_name, metric_type, strerror(errno));
    }
  }

  return 0;
}

int prom_metric_db_exists(pool *p, struct prom_dbh *dbh,
    const char *metric_name) {
  int res, xerrno;
  const char *stmt, *errstr = NULL;
  array_header *results;

  if (p == NULL ||
      dbh == NULL ||
      metric_name == NULL) {
    errno = EINVAL;
    return -1;
  }

  stmt = "SELECT metric_id FROM metrics WHERE metric_name = ?;";
  res = prom_db_prepare_stmt(p, dbh, stmt);
  if (res < 0) {
    return -1;
  }

  res = prom_db_bind_stmt(p, dbh, stmt, 1, PROM_DB_BIND_TYPE_TEXT,
    (void *) metric_name);
  if (res < 0) {
    return -1;
  }

  results = prom_db_exec_prepared_stmt(p, dbh, stmt, &errstr);
  xerrno = errno;
  (void) prom_db_finish_stmt(p, dbh, stmt);

  if (results == NULL) {
    pr_trace_msg(trace_channel, 7,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));
    errno = EPERM;
    return -1;
  }

  if (results->nelts == 0) {
    errno = ENOENT;
    return -1;
  }

  return 0;
}

int prom_metric_db_sample_exists(pool *p, struct prom_dbh *dbh,
    int64_t metric_id, const char *sample_labels) {
  int res, xerrno;
  const char *stmt, *errstr = NULL;
  array_header *results;

  if (sample_labels == NULL) {
    errno = EINVAL;
    return -1;
  }

  stmt = "SELECT sample_value FROM metric_samples WHERE metric_id = ? AND sample_labels = ?;";
  res = prom_db_prepare_stmt(p, dbh, stmt);
  if (res < 0) {
    return -1;
  }

  res = prom_db_bind_stmt(p, dbh, stmt, 1, PROM_DB_BIND_TYPE_INT,
    (void *) &metric_id);
  if (res < 0) {
    return -1;
  }

  res = prom_db_bind_stmt(p, dbh, stmt, 2, PROM_DB_BIND_TYPE_TEXT,
    (void *) sample_labels);
  if (res < 0) {
    return -1;
  }

  results = prom_db_exec_prepared_stmt(p, dbh, stmt, &errstr);
  xerrno = errno;
  (void) prom_db_finish_stmt(p, dbh, stmt);

  if (results == NULL) {
    pr_trace_msg(trace_channel, 7,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));
    errno = EPERM;
    return -1;
  }

  if (results->nelts == 0) {
    errno = ENOENT;
    return -1;
  }

  return 0;
}

static int db_sample_create(pool *p, struct prom_dbh *dbh, int64_t metric_id,
    double sample_val, const char *sample_labels) {
  int res, xerrno;
  const char *stmt, *errstr = NULL;
  array_header *results;

  stmt = "INSERT INTO metric_samples (metric_id, sample_value, sample_labels) VALUES (?, ?, ?);";
  res = prom_db_prepare_stmt(p, dbh, stmt);
  if (res < 0) {
    return -1;
  }

  res = prom_db_bind_stmt(p, dbh, stmt, 1, PROM_DB_BIND_TYPE_INT,
    (void *) &metric_id);
  if (res < 0) {
    return -1;
  }

  res = prom_db_bind_stmt(p, dbh, stmt, 2, PROM_DB_BIND_TYPE_DOUBLE,
    (void *) &sample_val);
  if (res < 0) {
    return -1;
  }

  res = prom_db_bind_stmt(p, dbh, stmt, 3, PROM_DB_BIND_TYPE_TEXT,
    (void *) sample_labels);
  if (res < 0) {
    return -1;
  }

  results = prom_db_exec_prepared_stmt(p, dbh, stmt, &errstr);
  xerrno = errno;
  (void) prom_db_finish_stmt(p, dbh, stmt);

  if (results == NULL) {
    pr_trace_msg(trace_channel, 7,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));
    errno = EPERM;
    return -1;
  }

  return 0;
}

static int db_sample_adj(pool *p, struct prom_dbh *dbh, const char *stmt,
    int64_t metric_id, double sample_val, const char *sample_labels) {
  int res, xerrno;
  const char *errstr = NULL;
  array_header *results;

  res = prom_db_prepare_stmt(p, dbh, stmt);
  if (res < 0) {
    return -1;
  }

  res = prom_db_bind_stmt(p, dbh, stmt, 1, PROM_DB_BIND_TYPE_DOUBLE,
    (void *) &sample_val);
  if (res < 0) {
    return -1;
  }

  res = prom_db_bind_stmt(p, dbh, stmt, 2, PROM_DB_BIND_TYPE_INT,
    (void *) &metric_id);
  if (res < 0) {
    return -1;
  }

  res = prom_db_bind_stmt(p, dbh, stmt, 3, PROM_DB_BIND_TYPE_TEXT,
    (void *) sample_labels);
  if (res < 0) {
    return -1;
  }

  results = prom_db_exec_prepared_stmt(p, dbh, stmt, &errstr);
  xerrno = errno;
  (void) prom_db_finish_stmt(p, dbh, stmt);

  if (results == NULL) {
    pr_trace_msg(trace_channel, 7,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));
    errno = EPERM;
    return -1;
  }

  return 0;
}

int prom_metric_db_sample_decr(pool *p, struct prom_dbh *dbh,
    int64_t metric_id, double sample_val, const char *sample_labels) {
  int res;
  const char *stmt;

  /* NOTE: Beware of race conditions with other processes, due to this
   * check-and-set sequence, for this sample.
   *
   * Consider using wrapping this in a BEGIN/COMMIT block; use EXCLUSIVE?
   */
  res = prom_metric_db_sample_exists(p, dbh, metric_id, sample_labels);
  if (res < 0) {
    double init_val = 0.0;

    if (errno != ENOENT) {
      return -1;
    }

    res = db_sample_create(p, dbh, metric_id, init_val, sample_labels);
    if (res < 0) {
      return -1;
    }
  }

  stmt = "UPDATE metric_samples SET sample_value = sample_value - ? WHERE metric_id = ? AND sample_labels = ?;";
  return db_sample_adj(p, dbh, stmt, metric_id, sample_val, sample_labels);
}

int prom_metric_db_sample_incr(pool *p, struct prom_dbh *dbh,
    int64_t metric_id, double sample_val, const char *sample_labels) {
  int res;
  const char *stmt;

  /* NOTE: Beware of race conditions with other processes, due to this
   * check-and-set sequence, for this sample.
   *
   * Consider using wrapping this in a BEGIN/COMMIT block; use EXCLUSIVE?
   */
  res = prom_metric_db_sample_exists(p, dbh, metric_id, sample_labels);
  if (res < 0) {
    double init_val = 0.0;

    if (errno != ENOENT) {
      return -1;
    }

    res = db_sample_create(p, dbh, metric_id, init_val, sample_labels);
    if (res < 0) {
      return -1;
    }
  }

  stmt = "UPDATE metric_samples SET sample_value = sample_value + ? WHERE metric_id = ? AND sample_labels = ?;";
  return db_sample_adj(p, dbh, stmt, metric_id, sample_val, sample_labels);
}

int prom_metric_db_sample_set(pool *p, struct prom_dbh *dbh,
    int64_t metric_id, double sample_val, const char *sample_labels) {
  int res;
  const char *stmt;

  /* NOTE: Beware of race conditions with other processes, due to this
   * check-and-set sequence, for this sample.
   *
   * Consider using wrapping this in a BEGIN/COMMIT block; use EXCLUSIVE?
   */
  res = prom_metric_db_sample_exists(p, dbh, metric_id, sample_labels);
  if (res < 0) {
    double init_val = 0.0;

    if (errno != ENOENT) {
      return -1;
    }

    res = db_sample_create(p, dbh, metric_id, init_val, sample_labels);
    if (res < 0) {
      return -1;
    }
  }

  stmt = "UPDATE metric_samples SET sample_value = ? WHERE metric_id = ? AND sample_labels = ?;";
  return db_sample_adj(p, dbh, stmt, metric_id, sample_val, sample_labels);
}

const array_header *prom_metric_db_sample_get(pool *p, struct prom_dbh *dbh,
    int64_t metric_id) {
  int res, xerrno;
  const char *stmt, *errstr = NULL;
  array_header *results;

  if (p == NULL |
      dbh == NULL) {
    errno = EINVAL;
    return NULL;
  }

  stmt = "SELECT sample_value, sample_labels FROM metric_samples WHERE metric_id = ? ORDER BY sample_labels ASC;";
  res = prom_db_prepare_stmt(p, dbh, stmt);
  if (res < 0) {
    return NULL;
  }

  res = prom_db_bind_stmt(p, dbh, stmt, 1, PROM_DB_BIND_TYPE_INT,
    (void *) &metric_id);
  if (res < 0) {
    return NULL;
  }

  results = prom_db_exec_prepared_stmt(p, dbh, stmt, &errstr);
  xerrno = errno;
  (void) prom_db_finish_stmt(p, dbh, stmt);

  if (results == NULL) {
    pr_trace_msg(trace_channel, 7,
      "error executing '%s': %s", stmt, errstr ? errstr : strerror(errno));
    errno = EPERM;
    return NULL;
  }

  return results;
}

int prom_metric_db_close(pool *p, struct prom_dbh *dbh) {
  if (p == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* TODO: Implement any necessary cleanup */

  if (dbh != NULL) {
    if (prom_db_close(p, dbh) < 0) {
      (void) pr_log_writefile(prometheus_logfd, MOD_PROMETHEUS_VERSION,
        "error detaching database with schema '%s': %s",
        PROM_METRICS_DB_SCHEMA_NAME, strerror(errno));
    }
  }

  return 0;
}

struct prom_dbh *prom_metric_db_open(pool *p, const char *tables_path) {
  int xerrno;
  struct prom_dbh *dbh;
  const char *db_path;

  if (p == NULL ||
      tables_path == NULL) {
    errno = EINVAL;
    return NULL;
  }

  db_path = pdircat(p, tables_path, "metrics.db", NULL);

  /* Make sure we have our own per-session database handle, per SQLite3
   * recommendation.
   */

  PRIVS_ROOT
  dbh = prom_db_open_readonly_with_version(p, db_path,
    PROM_METRICS_DB_SCHEMA_NAME, PROM_METRICS_DB_SCHEMA_VERSION, 0);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (dbh == NULL) {
    (void) pr_log_writefile(prometheus_logfd, MOD_PROMETHEUS_VERSION,
      "error opening database '%s' for schema '%s', version %u: %s",
      db_path, PROM_METRICS_DB_SCHEMA_NAME, PROM_METRICS_DB_SCHEMA_VERSION,
      strerror(xerrno));
    errno = xerrno;
    return NULL;
  }

  return dbh;
}

struct prom_dbh *prom_metric_db_init(pool *p, const char *tables_path,
    int flags) {
  int db_flags, res, xerrno = 0;
  const char *db_path = NULL;
  struct prom_dbh *dbh;

  if (p == NULL ||
      tables_path == NULL) {
    errno = EINVAL;
    return NULL;
  }

  db_path = pdircat(p, tables_path, "metrics.db", NULL);

  db_flags = PROM_DB_OPEN_FL_SCHEMA_VERSION_CHECK|PROM_DB_OPEN_FL_INTEGRITY_CHECK|PROM_DB_OPEN_FL_VACUUM;
  if (flags & PROM_DB_OPEN_FL_SKIP_VACUUM) {
    /* If the caller needs us to skip the vacuum, we will. */
    db_flags &= ~PROM_DB_OPEN_FL_VACUUM;
  }

  PRIVS_ROOT
  dbh = prom_db_open_with_version(p, db_path, PROM_METRICS_DB_SCHEMA_NAME,
    PROM_METRICS_DB_SCHEMA_VERSION, db_flags);
  xerrno = errno;
  PRIVS_RELINQUISH

  if (dbh == NULL) {
    (void) pr_log_pri(PR_LOG_NOTICE, MOD_PROMETHEUS_VERSION
      ": error opening database '%s' for schema '%s', version %u: %s",
      db_path, PROM_METRICS_DB_SCHEMA_NAME, PROM_METRICS_DB_SCHEMA_VERSION,
      strerror(xerrno));
    errno = xerrno;
    return NULL;
  }

  res = metrics_db_add_schema(p, dbh, db_path);
  if (res < 0) {
    xerrno = errno;
    (void) pr_log_debug(DEBUG0, MOD_PROMETHEUS_VERSION
      ": error creating schema in database '%s' for '%s': %s", db_path,
      PROM_METRICS_DB_SCHEMA_NAME, strerror(xerrno));
    (void) prom_db_close(p, dbh);
    errno = xerrno;
    return NULL;
  }

  res = metrics_db_truncate_tables(p, dbh);
  if (res < 0) {
    xerrno = errno;
    (void) prom_db_close(p, dbh);
    errno = xerrno;
    return NULL;
  }

  return dbh;
}
