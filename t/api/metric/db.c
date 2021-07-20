/*
 * ProFTPD - mod_prometheus API testsuite
 * Copyright (c) 2021 TJ Saunders <tj@castaglia.org>
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

/* Metric database API tests. */

#include "../tests.h"
#include "prometheus/db.h"
#include "prometheus/metric.h"
#include "prometheus/metric/db.h"

static pool *p = NULL;
static const char *test_dir = "/tmp/prt-mod_prometheus-test-db";

static int create_test_dir(void) {
  int res;
  mode_t perms;

  perms = 0770;
  res = mkdir(test_dir, perms);
  fail_unless(res == 0, "Failed to create tmp directory '%s': %s", test_dir,
    strerror(errno));

  res = chmod(test_dir, perms);
  fail_unless(res == 0, "Failed to set perms %04o on directory '%s': %s",
    perms, test_dir, strerror(errno));

  return 0;
}

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  (void) tests_rmpath(p, test_dir);
  (void) create_test_dir();

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("prometheus.db", 1, 20);
    pr_trace_set_levels("prometheus.metric.db", 1, 20);
  }

  mark_point();
  prom_db_init(p);
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("prometheus.db", 0, 0);
    pr_trace_set_levels("prometheus.metric.db", 0, 0);
  }

  prom_db_free();
  (void) tests_rmpath(p, test_dir);

  if (p != NULL) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  }
}

START_TEST (metric_db_close_test) {
  int res;

  mark_point();
  res = prom_metric_db_close(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = prom_metric_db_close(p, NULL);
  fail_unless(res == 0, "Failed to handle null dbh");
}
END_TEST

START_TEST (metric_db_init_test) {
  int res, flags = PROM_DB_OPEN_FL_SKIP_VACUUM;
  struct prom_dbh *dbh;

  mark_point();
  dbh = prom_metric_db_init(NULL, NULL, 0);
  fail_unless(dbh == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  dbh = prom_metric_db_init(p, NULL, 0);
  fail_unless(dbh == NULL, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  dbh = prom_metric_db_init(p, test_dir, flags);
  fail_unless(dbh != NULL, "Failed to init metrics db: %s", strerror(errno));

  res = prom_metric_db_close(p, dbh);
  fail_unless(res == 0, "Failed to close metrics db: %s", strerror(errno));
  (void) tests_rmpath(p, test_dir);
}
END_TEST

START_TEST (metric_db_open_test) {
  int res, flags = PROM_DB_OPEN_FL_SKIP_VACUUM;
  struct prom_dbh *dbh;

  (void) tests_rmpath(p, test_dir);
  (void) create_test_dir();

  mark_point();
  dbh = prom_metric_db_open(NULL, NULL);
  fail_unless(dbh == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  dbh = prom_metric_db_open(p, NULL);
  fail_unless(dbh == NULL, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  dbh = prom_metric_db_open(p, test_dir);
  fail_unless(dbh == NULL, "Failed to handle missing database");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  mark_point();
  dbh = prom_metric_db_init(p, test_dir, flags);
  fail_unless(dbh != NULL, "Failed to init metrics db: %s", strerror(errno));

  res = prom_metric_db_close(p, dbh);
  fail_unless(res == 0, "Failed to close metrics db: %s", strerror(errno));

  mark_point();
  dbh = prom_metric_db_open(p, test_dir);
  fail_unless(dbh != NULL, "Failed to open metrics db: %s", strerror(errno));

  res = prom_metric_db_close(p, dbh);
  fail_unless(res == 0, "Failed to close metrics db: %s", strerror(errno));
  (void) tests_rmpath(p, test_dir);
}
END_TEST

START_TEST (metric_db_exists_test) {
  int res, flags = PROM_DB_OPEN_FL_SKIP_VACUUM;
  const char *metric_name = "test_metric";
  struct prom_dbh *dbh;

  (void) tests_rmpath(p, test_dir);
  (void) create_test_dir();

  mark_point();
  res = prom_metric_db_exists(NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = prom_metric_db_exists(p, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null dbh");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  dbh = prom_metric_db_init(p, test_dir, flags);
  fail_unless(dbh != NULL, "Failed to init metrics db: %s", strerror(errno));

  mark_point();
  res = prom_metric_db_exists(p, dbh, metric_name);
  fail_unless(res < 0, "Failed to handle nonexistent metric");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  res = prom_metric_db_close(p, dbh);
  fail_unless(res == 0, "Failed to close metrics db: %s", strerror(errno));
  (void) tests_rmpath(p, test_dir);
}
END_TEST

START_TEST (metric_db_create_test) {
  int res, flags = PROM_DB_OPEN_FL_SKIP_VACUUM, metric_type = 1;
  const char *metric_name = "test_metric";
  int64_t metric_id = 0;
  struct prom_dbh *dbh;

  (void) tests_rmpath(p, test_dir);
  (void) create_test_dir();

  mark_point();
  res = prom_metric_db_create(NULL, NULL, NULL, 0, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = prom_metric_db_create(p, NULL, NULL, 0, NULL);
  fail_unless(res < 0, "Failed to handle null dbh");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  dbh = prom_metric_db_init(p, test_dir, flags);
  fail_unless(dbh != NULL, "Failed to init metrics db: %s", strerror(errno));

  mark_point();
  res = prom_metric_db_create(p, dbh, NULL, 0, NULL);
  fail_unless(res < 0, "Failed to handle null metric name");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = prom_metric_db_create(p, dbh, metric_name, metric_type, &metric_id);
  fail_unless(res == 0, "Failed to add db metric '%s': %s", metric_name,
    strerror(errno));

  mark_point();
  res = prom_metric_db_exists(p, dbh, metric_name);
  fail_unless(res == 0, "Failed to detect existing metric '%s': %s",
    metric_name, strerror(errno));

  res = prom_metric_db_close(p, dbh);
  fail_unless(res == 0, "Failed to close metrics db: %s", strerror(errno));
  (void) tests_rmpath(p, test_dir);
}
END_TEST

START_TEST (metric_db_sample_exists_test) {
}
END_TEST

START_TEST (metric_db_sample_get_test) {
  int res, flags = PROM_DB_OPEN_FL_SKIP_VACUUM;
  struct prom_dbh *dbh;
  array_header *results;

  (void) tests_rmpath(p, test_dir);
  (void) create_test_dir();

  mark_point();
  results = prom_metric_db_sample_get(NULL, NULL, 0);
  fail_unless(results == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  results = prom_metric_db_sample_get(p, NULL, 0);
  fail_unless(results == NULL, "Failed to handle null dbh");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  dbh = prom_metric_db_init(p, test_dir, flags);
  fail_unless(dbh != NULL, "Failed to init metrics db: %s", strerror(errno));

  mark_point();
  results = prom_metric_db_sample_get(p, dbh, 0);
  fail_unless(results != NULL, "Failed to get metric samples: %s",
    strerror(errno));
  fail_unless(results->nelts == 0,
    "Expected zero results, got %d", results->nelts);

  res = prom_metric_db_close(p, dbh);
  fail_unless(res == 0, "Failed to close metrics db: %s", strerror(errno));
  (void) tests_rmpath(p, test_dir);
}
END_TEST

START_TEST (metric_db_sample_decr_test) {
  int res, flags = PROM_DB_OPEN_FL_SKIP_VACUUM;
  int64_t metric_id = 24;
  double decr_val = 76.24, sample_val;
  struct prom_dbh *dbh;
  array_header *results;
  char **elts, *ptr;

  (void) tests_rmpath(p, test_dir);
  (void) create_test_dir();

  mark_point();
  res = prom_metric_db_sample_decr(NULL, NULL, 0, 0.0, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = prom_metric_db_sample_decr(p, NULL, 0, 0.0, NULL);
  fail_unless(res < 0, "Failed to handle null dbh");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  dbh = prom_metric_db_init(p, test_dir, flags);
  fail_unless(dbh != NULL, "Failed to init metrics db: %s", strerror(errno));

  mark_point();
  res = prom_metric_db_sample_decr(p, dbh, metric_id, decr_val, NULL);
  fail_unless(res == 0, "Failed to decrement metric ID %ld: %s",
    metric_id, strerror(errno));

  mark_point();
  results = prom_metric_db_sample_get(p, dbh, metric_id);
  fail_unless(results != NULL, "Failed to get samples for metric ID %ld: %s",
    metric_id, strerror(errno));
  fail_unless(results->nelts == 2, "Expected results->nelts = 2, got %d",
    results->nelts);

  elts = results->elts;
  fail_unless(elts[0] != NULL, "Expected sample value, got NULL");

  ptr = NULL;
  sample_val = strtod(elts[0], &ptr);
  fail_if(ptr != NULL && *ptr, "Expected double sample value, got '%s'",
    elts[0]);
  fail_unless(-sample_val == decr_val, "Expected sample value %lf, got %lf",
    decr_val, sample_val);

  fail_unless(elts[1] == NULL, "Expected null sample_labels, got '%s'",
    elts[1]);

  res = prom_metric_db_close(p, dbh);
  fail_unless(res == 0, "Failed to close metrics db: %s", strerror(errno));
  (void) tests_rmpath(p, test_dir);
}
END_TEST

START_TEST (metric_db_sample_incr_test) {
  int res, flags = PROM_DB_OPEN_FL_SKIP_VACUUM;
  int64_t metric_id = 42;
  double incr_val = 24.76, sample_val;
  struct prom_dbh *dbh;
  array_header *results;
  char **elts, *ptr;

  (void) tests_rmpath(p, test_dir);
  (void) create_test_dir();

  mark_point();
  res = prom_metric_db_sample_incr(NULL, NULL, 0, 0.0, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = prom_metric_db_sample_incr(p, NULL, 0, 0.0, NULL);
  fail_unless(res < 0, "Failed to handle null dbh");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  dbh = prom_metric_db_init(p, test_dir, flags);
  fail_unless(dbh != NULL, "Failed to init metrics db: %s", strerror(errno));

  mark_point();
  res = prom_metric_db_sample_incr(p, dbh, metric_id, incr_val, NULL);
  fail_unless(res == 0, "Failed to increment metric ID %ld: %s",
    metric_id, strerror(errno));

  mark_point();
  results = prom_metric_db_sample_get(p, dbh, metric_id);
  fail_unless(results != NULL, "Failed to get samples for metric ID %ld: %s",
    metric_id, strerror(errno));
  fail_unless(results->nelts == 2, "Expected results->nelts = 2, got %d",
    results->nelts);

  elts = results->elts;
  fail_unless(elts[0] != NULL, "Expected sample value, got NULL");

  ptr = NULL;
  sample_val = strtod(elts[0], &ptr);
  fail_if(ptr != NULL && *ptr, "Expected double sample value, got '%s'",
    elts[0]);
  fail_unless(sample_val == incr_val, "Expected sample value %lf, got %lf",
    incr_val, sample_val);

  fail_unless(elts[1] == NULL, "Expected null sample_labels, got '%s'",
    elts[1]);

  res = prom_metric_db_close(p, dbh);
  fail_unless(res == 0, "Failed to close metrics db: %s", strerror(errno));
  (void) tests_rmpath(p, test_dir);
}
END_TEST

Suite *tests_get_metric_db_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("metric.db");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, metric_db_close_test);
  tcase_add_test(testcase, metric_db_init_test);
  tcase_add_test(testcase, metric_db_open_test);

  tcase_add_test(testcase, metric_db_exists_test);
  tcase_add_test(testcase, metric_db_create_test);

  tcase_add_test(testcase, metric_db_sample_exists_test);
  tcase_add_test(testcase, metric_db_sample_get_test);
  tcase_add_test(testcase, metric_db_sample_decr_test);
  tcase_add_test(testcase, metric_db_sample_incr_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
