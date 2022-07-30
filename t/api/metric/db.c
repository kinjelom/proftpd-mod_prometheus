/*
 * ProFTPD - mod_prometheus API testsuite
 * Copyright (c) 2021-2022 TJ Saunders <tj@castaglia.org>
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

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  (void) tests_rmpath(p, test_dir);
  (void) tests_mkpath(p, test_dir);

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
  ck_assert_msg(res < 0, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = prom_metric_db_close(p, NULL);
  ck_assert_msg(res == 0, "Failed to handle null dbh");
}
END_TEST

START_TEST (metric_db_init_test) {
  int res, flags = PROM_DB_OPEN_FL_SKIP_VACUUM;
  struct prom_dbh *dbh;

  mark_point();
  dbh = prom_metric_db_init(NULL, NULL, 0);
  ck_assert_msg(dbh == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  dbh = prom_metric_db_init(p, NULL, 0);
  ck_assert_msg(dbh == NULL, "Failed to handle null path");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  dbh = prom_metric_db_init(p, test_dir, flags);
  ck_assert_msg(dbh != NULL, "Failed to init metrics db: %s", strerror(errno));

  res = prom_metric_db_close(p, dbh);
  ck_assert_msg(res == 0, "Failed to close metrics db: %s", strerror(errno));
  (void) tests_rmpath(p, test_dir);
}
END_TEST

START_TEST (metric_db_open_test) {
  int res, flags = PROM_DB_OPEN_FL_SKIP_VACUUM;
  struct prom_dbh *dbh;

  (void) tests_rmpath(p, test_dir);
  (void) tests_mkpath(p, test_dir);

  mark_point();
  dbh = prom_metric_db_open(NULL, NULL);
  ck_assert_msg(dbh == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  dbh = prom_metric_db_open(p, NULL);
  ck_assert_msg(dbh == NULL, "Failed to handle null path");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  dbh = prom_metric_db_open(p, test_dir);
  ck_assert_msg(dbh == NULL, "Failed to handle missing database");
  ck_assert_msg(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  mark_point();
  dbh = prom_metric_db_init(p, test_dir, flags);
  ck_assert_msg(dbh != NULL, "Failed to init metrics db: %s", strerror(errno));

  res = prom_metric_db_close(p, dbh);
  ck_assert_msg(res == 0, "Failed to close metrics db: %s", strerror(errno));

  mark_point();
  dbh = prom_metric_db_open(p, test_dir);
  ck_assert_msg(dbh != NULL, "Failed to open metrics db: %s", strerror(errno));

  res = prom_metric_db_close(p, dbh);
  ck_assert_msg(res == 0, "Failed to close metrics db: %s", strerror(errno));
  (void) tests_rmpath(p, test_dir);
}
END_TEST

START_TEST (metric_db_exists_test) {
  int res, flags = PROM_DB_OPEN_FL_SKIP_VACUUM;
  const char *metric_name = "test_metric";
  struct prom_dbh *dbh;

  (void) tests_rmpath(p, test_dir);
  (void) tests_mkpath(p, test_dir);

  mark_point();
  res = prom_metric_db_exists(NULL, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = prom_metric_db_exists(p, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle null dbh");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  dbh = prom_metric_db_init(p, test_dir, flags);
  ck_assert_msg(dbh != NULL, "Failed to init metrics db: %s", strerror(errno));

  mark_point();
  res = prom_metric_db_exists(p, dbh, metric_name);
  ck_assert_msg(res < 0, "Failed to handle nonexistent metric");
  ck_assert_msg(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  res = prom_metric_db_close(p, dbh);
  ck_assert_msg(res == 0, "Failed to close metrics db: %s", strerror(errno));
  (void) tests_rmpath(p, test_dir);
}
END_TEST

START_TEST (metric_db_create_test) {
  int res, flags = PROM_DB_OPEN_FL_SKIP_VACUUM, metric_type = 1;
  const char *metric_name = "test_metric";
  int64_t metric_id = 0;
  struct prom_dbh *dbh;

  (void) tests_rmpath(p, test_dir);
  (void) tests_mkpath(p, test_dir);

  mark_point();
  res = prom_metric_db_create(NULL, NULL, NULL, 0, NULL);
  ck_assert_msg(res < 0, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = prom_metric_db_create(p, NULL, NULL, 0, NULL);
  ck_assert_msg(res < 0, "Failed to handle null dbh");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  dbh = prom_metric_db_init(p, test_dir, flags);
  ck_assert_msg(dbh != NULL, "Failed to init metrics db: %s", strerror(errno));

  mark_point();
  res = prom_metric_db_create(p, dbh, NULL, 0, NULL);
  ck_assert_msg(res < 0, "Failed to handle null metric name");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = prom_metric_db_create(p, dbh, metric_name, metric_type, &metric_id);
  ck_assert_msg(res == 0, "Failed to add db metric '%s': %s", metric_name,
    strerror(errno));

  mark_point();
  res = prom_metric_db_exists(p, dbh, metric_name);
  ck_assert_msg(res == 0, "Failed to detect existing metric '%s': %s",
    metric_name, strerror(errno));

  res = prom_metric_db_close(p, dbh);
  ck_assert_msg(res == 0, "Failed to close metrics db: %s", strerror(errno));
  (void) tests_rmpath(p, test_dir);
}
END_TEST

START_TEST (metric_db_sample_exists_test) {
}
END_TEST

START_TEST (metric_db_sample_get_test) {
  int res, flags = PROM_DB_OPEN_FL_SKIP_VACUUM;
  struct prom_dbh *dbh;
  const array_header *results;

  (void) tests_rmpath(p, test_dir);
  (void) tests_mkpath(p, test_dir);

  mark_point();
  results = prom_metric_db_sample_get(NULL, NULL, 0);
  ck_assert_msg(results == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  results = prom_metric_db_sample_get(p, NULL, 0);
  ck_assert_msg(results == NULL, "Failed to handle null dbh");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  dbh = prom_metric_db_init(p, test_dir, flags);
  ck_assert_msg(dbh != NULL, "Failed to init metrics db: %s", strerror(errno));

  mark_point();
  results = prom_metric_db_sample_get(p, dbh, 0);
  ck_assert_msg(results != NULL, "Failed to get metric samples: %s",
    strerror(errno));
  ck_assert_msg(results->nelts == 0,
    "Expected zero results, got %d", results->nelts);

  res = prom_metric_db_close(p, dbh);
  ck_assert_msg(res == 0, "Failed to close metrics db: %s", strerror(errno));
  (void) tests_rmpath(p, test_dir);
}
END_TEST

START_TEST (metric_db_sample_decr_test) {
  int res, flags = PROM_DB_OPEN_FL_SKIP_VACUUM;
  int64_t metric_id = 24;
  double decr_val = 76.24, sample_val;
  struct prom_dbh *dbh;
  const array_header *results;
  char **elts, *ptr;

  (void) tests_rmpath(p, test_dir);
  (void) tests_mkpath(p, test_dir);

  mark_point();
  res = prom_metric_db_sample_decr(NULL, NULL, 0, 0.0, NULL);
  ck_assert_msg(res < 0, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = prom_metric_db_sample_decr(p, NULL, 0, 0.0, NULL);
  ck_assert_msg(res < 0, "Failed to handle null dbh");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  dbh = prom_metric_db_init(p, test_dir, flags);
  ck_assert_msg(dbh != NULL, "Failed to init metrics db: %s", strerror(errno));

  mark_point();
  res = prom_metric_db_sample_decr(p, dbh, metric_id, decr_val, NULL);
  ck_assert_msg(res < 0, "Failed to handle null sample labels");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = prom_metric_db_sample_decr(p, dbh, metric_id, decr_val, "");
  ck_assert_msg(res == 0, "Failed to decrement metric ID %ld: %s",
    metric_id, strerror(errno));

  mark_point();
  results = prom_metric_db_sample_get(p, dbh, metric_id);
  ck_assert_msg(results != NULL, "Failed to get samples for metric ID %ld: %s",
    metric_id, strerror(errno));
  ck_assert_msg(results->nelts == 2, "Expected results->nelts = 2, got %d",
    results->nelts);

  elts = results->elts;
  ck_assert_msg(elts[0] != NULL, "Expected sample value, got NULL");

  ptr = NULL;
  sample_val = strtod(elts[0], &ptr);
  ck_assert_msg(ptr == NULL || !*ptr, "Expected double sample value, got '%s'",
    elts[0]);
  ck_assert_msg((int) -sample_val == (int) decr_val,
    "Expected sample value %lf, got %lf", decr_val, sample_val);

  ck_assert_msg(elts[1] != NULL, "Expected sample_labels, got null");
  ck_assert_msg(strcmp(elts[1], "") == 0,
    "Expected sample labels '', got '%s'", elts[1]);

  res = prom_metric_db_close(p, dbh);
  ck_assert_msg(res == 0, "Failed to close metrics db: %s", strerror(errno));
  (void) tests_rmpath(p, test_dir);
}
END_TEST

START_TEST (metric_db_sample_incr_test) {
  int res, flags = PROM_DB_OPEN_FL_SKIP_VACUUM;
  int64_t metric_id = 42;
  double incr_val = 24.76, sample_val;
  struct prom_dbh *dbh;
  const array_header *results;
  char **elts, *ptr;

  (void) tests_rmpath(p, test_dir);
  (void) tests_mkpath(p, test_dir);

  mark_point();
  res = prom_metric_db_sample_incr(NULL, NULL, 0, 0.0, NULL);
  ck_assert_msg(res < 0, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = prom_metric_db_sample_incr(p, NULL, 0, 0.0, NULL);
  ck_assert_msg(res < 0, "Failed to handle null dbh");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  dbh = prom_metric_db_init(p, test_dir, flags);
  ck_assert_msg(dbh != NULL, "Failed to init metrics db: %s", strerror(errno));

  mark_point();
  res = prom_metric_db_sample_incr(p, dbh, metric_id, incr_val, NULL);
  ck_assert_msg(res < 0, "Failed to handle null sample labels");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = prom_metric_db_sample_incr(p, dbh, metric_id, incr_val, "");
  ck_assert_msg(res == 0, "Failed to increment metric ID %ld: %s",
    metric_id, strerror(errno));

  mark_point();
  results = prom_metric_db_sample_get(p, dbh, metric_id);
  ck_assert_msg(results != NULL, "Failed to get samples for metric ID %ld: %s",
    metric_id, strerror(errno));
  ck_assert_msg(results->nelts == 2, "Expected results->nelts = 2, got %d",
    results->nelts);

  elts = results->elts;
  ck_assert_msg(elts[0] != NULL, "Expected sample value, got NULL");

  ptr = NULL;
  sample_val = strtod(elts[0], &ptr);
  ck_assert_msg(ptr == NULL || !*ptr, "Expected double sample value, got '%s'",
    elts[0]);
  ck_assert_msg((int) sample_val == (int) incr_val,
    "Expected sample value %lf, got %lf", incr_val, sample_val);

  ck_assert_msg(elts[1] != NULL, "Expected sample_labels, got null");
  ck_assert_msg(strcmp(elts[1], "") == 0,
    "Expected sample labels '', got '%s'", elts[1]);

  res = prom_metric_db_close(p, dbh);
  ck_assert_msg(res == 0, "Failed to close metrics db: %s", strerror(errno));
  (void) tests_rmpath(p, test_dir);
}
END_TEST

START_TEST (metric_db_sample_set_test) {
  int res, flags = PROM_DB_OPEN_FL_SKIP_VACUUM;
  int64_t metric_id = 84;
  double set_val = 3.1514, sample_val;
  struct prom_dbh *dbh;
  const array_header *results;
  char **elts, *ptr;

  (void) tests_rmpath(p, test_dir);
  (void) tests_mkpath(p, test_dir);

  mark_point();
  res = prom_metric_db_sample_set(NULL, NULL, 0, 0.0, NULL);
  ck_assert_msg(res < 0, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = prom_metric_db_sample_set(p, NULL, 0, 0.0, NULL);
  ck_assert_msg(res < 0, "Failed to handle null dbh");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  dbh = prom_metric_db_init(p, test_dir, flags);
  ck_assert_msg(dbh != NULL, "Failed to init metrics db: %s", strerror(errno));

  mark_point();
  res = prom_metric_db_sample_set(p, dbh, metric_id, set_val, NULL);
  ck_assert_msg(res < 0, "Failed to handle null sample labels");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = prom_metric_db_sample_set(p, dbh, metric_id, set_val, "");
  ck_assert_msg(res == 0, "Failed to set metric ID %ld: %s",
    metric_id, strerror(errno));

  mark_point();
  results = prom_metric_db_sample_get(p, dbh, metric_id);
  ck_assert_msg(results != NULL, "Failed to get samples for metric ID %ld: %s",
    metric_id, strerror(errno));
  ck_assert_msg(results->nelts == 2, "Expected results->nelts = 2, got %d",
    results->nelts);

  elts = results->elts;
  ck_assert_msg(elts[0] != NULL, "Expected sample value, got NULL");

  ptr = NULL;
  sample_val = strtod(elts[0], &ptr);
  ck_assert_msg(ptr == NULL || !*ptr, "Expected double sample value, got '%s'",
    elts[0]);
  ck_assert_msg((int) sample_val == (int) set_val,
    "Expected sample value %lf, got %lf", set_val, sample_val);

  ck_assert_msg(elts[1] != NULL, "Expected sample_labels, got null");
  ck_assert_msg(strcmp(elts[1], "") == 0,
    "Expected sample labels '', got '%s'", elts[1]);

  res = prom_metric_db_close(p, dbh);
  ck_assert_msg(res == 0, "Failed to close metrics db: %s", strerror(errno));
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
  tcase_add_test(testcase, metric_db_sample_set_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
