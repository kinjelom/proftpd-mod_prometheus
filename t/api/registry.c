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

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("prometheus.registry", 1, 20);
  }

  mark_point();
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("prometheus.registry", 0, 0);
  }

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

Suite *tests_get_registry_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("registry");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, registry_free_test);
  tcase_add_test(testcase, registry_init_test);

  /* TODO */
#if 0
  tcase_add_test(testcase, registry_get_metric_test);
  tcase_add_test(testcase, registry_remove_metric_test);
  tcase_add_test(testcase, registry_add_metric_test);
  tcase_add_test(testcase, registry_sort_metrics_test);

  tcase_add_test(testcase, registry_set_dbh_test);

  tcase_add_test(testcase, registry_get_text_test);
#endif

  suite_add_tcase(suite, testcase);
  return suite;
}
