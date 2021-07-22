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

/* Registry API tests. */

#include "tests.h"
#include "prometheus/registry.h"
#include "prometheus/metric/db.h"

static pool *p = NULL;
static const char *test_dir = "/tmp/prt-mod_prometheus-test-registry";

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  (void) tests_rmpath(p, test_dir);
  (void) tests_mkpath(p, test_dir);

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("prometheus.db", 1, 20);
    pr_trace_set_levels("prometheus.registry", 1, 20);
  }

  mark_point();
  prom_db_init(p);
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("prometheus.db", 0, 0);
    pr_trace_set_levels("prometheus.registry", 0, 0);
  }

  prom_db_free();
  (void) tests_rmpath(p, test_dir);

  if (p != NULL) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  }
}

START_TEST (registry_free_test) {
  int res;

  mark_point();
  res = prom_registry_free(NULL);
  fail_unless(res < 0, "Failed to handle null registry");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (registry_init_test) {
  int res;
  const char *name;
  struct prom_registry *registry;

  mark_point();
  registry = prom_registry_init(NULL, NULL);
  fail_unless(registry == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  registry = prom_registry_init(p, NULL);
  fail_unless(registry == NULL, "Failed to handle null name");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  registry = prom_registry_init(p, "test");
  fail_unless(registry != NULL, "Failed to create registry: %s",
    strerror(errno));

  mark_point();
  name = prom_registry_get_name(NULL);
  fail_unless(name == NULL, "Failed to handle null registry");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  name = prom_registry_get_name(registry);
  fail_unless(name != NULL, "Failed to get name: %s", strerror(errno));
  fail_unless(strcmp(name, "test") == 0, "Expected 'test', got '%s'",
    name);

  res = prom_registry_free(registry);
  fail_unless(res == 0, "Failed to free registry: %s", strerror(errno));
}
END_TEST

START_TEST (registry_get_metric_test) {
  struct prom_registry *registry;
  const struct prom_metric *metric;

  mark_point();
  metric = prom_registry_get_metric(NULL, NULL);
  fail_unless(metric == NULL, "Failed to handle null registry");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  registry = prom_registry_init(p, "test");
  fail_unless(registry != NULL, "Failed to create registry: %s",
    strerror(errno));

  mark_point();
  metric = prom_registry_get_metric(registry, NULL);
  fail_unless(metric == NULL, "Failed to handle null metric name");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  prom_registry_free(registry);
}
END_TEST

START_TEST (registry_add_metric_test) {
  int res;
  struct prom_registry *registry;
  char *metric_name;
  struct prom_metric *metric;
  struct prom_dbh *dbh;

  mark_point();
  res = prom_registry_add_metric(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null registry");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  registry = prom_registry_init(p, "test");
  fail_unless(registry != NULL, "Failed to create registry: %s",
    strerror(errno));

  mark_point();
  res = prom_registry_add_metric(registry, NULL);
  fail_unless(res < 0, "Failed to handle null metric");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  /* For purposes of testing, we don't need a real dbh here. */
  mark_point();
  metric_name = "metric";
  dbh = palloc(p, 8);
  metric = prom_metric_create(p, metric_name, dbh);
  fail_unless(metric != NULL, "Failed to create metric: %s", strerror(errno));

  res = prom_registry_add_metric(registry, metric);
  fail_unless(res == 0, "Failed to add metric: %s", strerror(errno));

  mark_point();
  metric = (struct prom_metric *) prom_registry_get_metric(registry,
    metric_name);
  fail_unless(metric != NULL, "Failed to get metric: %s", strerror(errno));

  prom_registry_free(registry);
}
END_TEST

START_TEST (registry_sort_metrics_test) {
  int res;
  struct prom_registry *registry;
  struct prom_metric *first_metric, *second_metric;
  struct prom_dbh *dbh;

  mark_point();
  res = prom_registry_sort_metrics(NULL);
  fail_unless(res < 0, "Failed to handle null registry");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  registry = prom_registry_init(p, "test");
  fail_unless(registry != NULL, "Failed to create registry: %s",
    strerror(errno));

  /* For purposes of testing, we don't need a real dbh here. */
  mark_point();
  dbh = palloc(p, 8);
  first_metric = prom_metric_create(p, "first", dbh);
  fail_unless(first_metric != NULL, "Failed to create metric: %s",
    strerror(errno));

  res = prom_registry_add_metric(registry, first_metric);
  fail_unless(res == 0, "Failed to add metric: %s", strerror(errno));

  mark_point();
  res = prom_registry_sort_metrics(registry);
  fail_unless(res == 0, "Failed to sort metrics: %s", strerror(errno));

  mark_point();
  second_metric = prom_metric_create(p, "second", dbh);
  fail_unless(second_metric != NULL, "Failed to create metric: %s",
    strerror(errno));

  res = prom_registry_add_metric(registry, second_metric);
  fail_unless(res == 0, "Failed to add metric: %s", strerror(errno));

  res = prom_registry_sort_metrics(registry);
  fail_unless(res == 0, "Failed to sort metrics: %s", strerror(errno));

  prom_registry_free(registry);
}
END_TEST

START_TEST (registry_set_dbh_test) {
  int res;
  struct prom_registry *registry;
  struct prom_dbh *dbh;

  mark_point();
  res = prom_registry_set_dbh(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null registry");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  registry = prom_registry_init(p, "test");
  fail_unless(registry != NULL, "Failed to create registry: %s",
    strerror(errno));

  mark_point();
  res = prom_registry_set_dbh(registry, NULL);
  fail_unless(res < 0, "Failed to handle null registry");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  /* For purposes of testing, we don't need a real dbh here. */
  mark_point();
  dbh = palloc(p, 8);
  res = prom_registry_set_dbh(registry, dbh);
  fail_unless(res == 0, "Failed to handle set dbh: %s", strerror(errno));

  prom_registry_free(registry);
}
END_TEST

START_TEST (registry_get_text_test) {
  const char *text;
  struct prom_registry *registry;

  mark_point();
  text = prom_registry_get_text(NULL, NULL);
  fail_unless(text == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  text = prom_registry_get_text(p, NULL);
  fail_unless(text == NULL, "Failed to handle null registry");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  registry = prom_registry_init(p, "test");
  fail_unless(registry != NULL, "Failed to create registry: %s",
    strerror(errno));

  mark_point();
  text = prom_registry_get_text(p, registry);
  fail_unless(text == NULL, "Failed to handle absent metrics");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  prom_registry_free(registry);
}
END_TEST

START_TEST (registry_get_text_with_metrics_test) {
  int res;
  const char *text;
  struct prom_registry *registry;
  struct prom_metric *metric;
  struct prom_dbh *dbh;

  (void) tests_rmpath(p, test_dir);
  (void) tests_mkpath(p, test_dir);

  mark_point();
  registry = prom_registry_init(p, "test");
  fail_unless(registry != NULL, "Failed to create registry: %s",
    strerror(errno));

  mark_point();
  dbh = prom_metric_init(p, test_dir);
  fail_unless(dbh != NULL, "Failed to init metrics: %s", strerror(errno));

  mark_point();
  metric = prom_metric_create(p, "metric", dbh);
  fail_unless(metric != NULL, "Failed to create metric: %s", strerror(errno));

  mark_point();
  res = prom_registry_add_metric(registry, metric);
  fail_unless(res == 0, "Failed to register metric: %s", strerror(errno));

  mark_point();
  res = prom_metric_add_counter(metric, "total", "testing");
  fail_unless(res == 0, "Failed to add counter to metric: %s", strerror(errno));

  mark_point();
  res = prom_metric_incr(p, metric, 1, NULL);
  fail_unless(res == 0, "Failed to increment metric: %s", strerror(errno));

  mark_point();
  text = prom_registry_get_text(p, registry);
  fail_unless(text != NULL, "Failed to get registry text: %s", strerror(errno));

  /* Use strstr(3) to assert bits of text. */
  fail_unless(strstr(text, "# HELP test_metric_total") != NULL,
    "Expected metric help, got '%s'", text);
  fail_unless(strstr(text, "# TYPE test_metric_total counter") != NULL,
    "Expected metric type, got '%s'", text);
  fail_unless(strstr(text, "test_metric_total 1") != NULL,
    "Expected metric sample, got '%s'", text);

  prom_registry_free(registry);
  prom_db_close(p, dbh);
  (void) tests_rmpath(p, test_dir);
}
END_TEST

START_TEST (registry_get_text_with_metrics_readonly_test) {
  int res;
  const char *text;
  struct prom_registry *registry;
  struct prom_metric *metric;
  struct prom_dbh *dbh;

  (void) tests_rmpath(p, test_dir);
  (void) tests_mkpath(p, test_dir);

  mark_point();
  registry = prom_registry_init(p, "test");
  fail_unless(registry != NULL, "Failed to create registry: %s",
    strerror(errno));

  mark_point();
  dbh = prom_metric_init(p, test_dir);
  fail_unless(dbh != NULL, "Failed to init metrics: %s", strerror(errno));

  mark_point();
  metric = prom_metric_create(p, "metric", dbh);
  fail_unless(metric != NULL, "Failed to create metric: %s", strerror(errno));

  mark_point();
  res = prom_registry_add_metric(registry, metric);
  fail_unless(res == 0, "Failed to register metric: %s", strerror(errno));

  mark_point();
  res = prom_metric_add_counter(metric, "total", "testing");
  fail_unless(res == 0, "Failed to add counter to metric: %s", strerror(errno));

  mark_point();
  res = prom_metric_incr(p, metric, 1, NULL);
  fail_unless(res == 0, "Failed to increment metric: %s", strerror(errno));

  mark_point();

  /* Now, close that dbh.  Open a readonly one, set it in the registry.
   * This approximates what happens with the exporter process.
   */
  (void) prom_db_close(p, dbh);
  dbh = prom_metric_db_open(p, test_dir);
  fail_unless(dbh != NULL, "Failed to open readonly dbh: %s", strerror(errno));

  mark_point();
  res = prom_registry_set_dbh(registry, dbh);
  fail_unless(res == 0, "Failed to set registry dbh: %s", strerror(errno));

  mark_point();
  text = prom_registry_get_text(p, registry);
  fail_unless(text != NULL, "Failed to get registry text: %s", strerror(errno));

  /* Use strstr(3) to assert bits of text. */
  fail_unless(strstr(text, "# HELP test_metric_total") != NULL,
    "Expected metric help, got '%s'", text);
  fail_unless(strstr(text, "# TYPE test_metric_total counter") != NULL,
    "Expected metric type, got '%s'", text);
  fail_unless(strstr(text, "test_metric_total 1") != NULL,
    "Expected metric sample, got '%s'", text);

  prom_registry_free(registry);
  prom_db_close(p, dbh);
  (void) tests_rmpath(p, test_dir);
}
END_TEST

Suite *tests_get_registry_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("registry");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, registry_free_test);
  tcase_add_test(testcase, registry_init_test);

  tcase_add_test(testcase, registry_get_metric_test);
  tcase_add_test(testcase, registry_add_metric_test);
  tcase_add_test(testcase, registry_sort_metrics_test);
  tcase_add_test(testcase, registry_set_dbh_test);

  tcase_add_test(testcase, registry_get_text_test);
  tcase_add_test(testcase, registry_get_text_with_metrics_test);
  tcase_add_test(testcase, registry_get_text_with_metrics_readonly_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
