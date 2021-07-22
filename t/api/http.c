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

/* HTTP API tests. */

#include "tests.h"
#include "prometheus/http.h"
#include "prometheus/registry.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("prometheus.http", 1, 20);
  }

  mark_point();
  prom_http_init(p);
}

static void tear_down(void) {
  prom_http_free();

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("prometheus.http", 0, 0);
  }

  if (p != NULL) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  }
}

START_TEST (http_init_test) {
  int res;

  mark_point();
  res = prom_http_init(NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = prom_http_init(p);
  fail_unless(res == 0, "Failed to init HTTP API: %s", strerror(errno));
}
END_TEST

START_TEST (http_free_test) {
  int res;

  mark_point();
  res = prom_http_free();
  fail_unless(res == 0, "Failed to free HTTP API: %s", strerror(errno));
}
END_TEST

START_TEST (http_stop_test) {
  int res;

  mark_point();
  res = prom_http_stop(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = prom_http_stop(p, NULL);
  fail_unless(res < 0, "Failed to handle null http");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (http_start_test) {
  int res;
  pr_netaddr_t *addr;
  struct prom_http *http;
  struct prom_registry *registry;

  mark_point();
  http = prom_http_start(NULL, NULL, NULL);
  fail_unless(http == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  http = prom_http_start(p, NULL, NULL);
  fail_unless(http == NULL, "Failed to handle null addr");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  addr = pr_netaddr_alloc(p);
  pr_netaddr_set_family(addr, AF_INET);
  pr_netaddr_set_sockaddr_any(addr);
  pr_netaddr_set_port2(addr, 0);

  http = prom_http_start(p, addr, NULL);
  fail_unless(http == NULL, "Failed to handle null registry");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();

  /* Note: We don't need a real registry here, just a non-null pointer. */
  registry = pcalloc(p, 8);
  http = prom_http_start(p, addr, registry);
  fail_unless(http != NULL, "Failed to start http: %s", strerror(errno));

  mark_point();
  res = prom_http_stop(p, http);
  fail_unless(res == 0, "Failed to stop http: %s", strerror(errno));
}
END_TEST

START_TEST (http_run_loop_test) {
  int res;

  mark_point();
  res = prom_http_run_loop(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = prom_http_run_loop(p, NULL);
  fail_unless(res < 0, "Failed to handle null http");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

Suite *tests_get_http_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("http");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, http_init_test);
  tcase_add_test(testcase, http_free_test);
  tcase_add_test(testcase, http_stop_test);
  tcase_add_test(testcase, http_start_test);
  tcase_add_test(testcase, http_run_loop_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
