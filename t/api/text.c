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

/* Text API tests. */

#include "tests.h"
#include "prometheus/text.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("prometheus.text", 1, 20);
  }

  mark_point();
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("prometheus.text", 0, 0);
  }

  if (p != NULL) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  }
}

START_TEST (text_destroy_test) {
  int res;

  mark_point();
  res = prom_text_destroy(NULL);
  ck_assert_msg(res < 0, "Failed to handle null text");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (text_create_test) {
  int res;
  struct prom_text *text;

  mark_point();
  text = prom_text_create(NULL);
  ck_assert_msg(text == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  text = prom_text_create(p);
  ck_assert_msg(text != NULL, "Failed to create text: %s", strerror(errno));

  res = prom_text_destroy(text);
  ck_assert_msg(res == 0, "Failed to destroy text: %s", strerror(errno));
}
END_TEST

START_TEST (text_get_str_test) {
  char *res;
  struct prom_text *text;

  mark_point();
  res = prom_text_get_str(NULL, NULL, NULL);
  ck_assert_msg(res == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = prom_text_get_str(p, NULL, NULL);
  ck_assert_msg(res == NULL, "Failed to handle null text");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  text = prom_text_create(p);
  res = prom_text_get_str(p, text, NULL);
  ck_assert_msg(res == NULL, "Failed to handle absent text");
  ck_assert_msg(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  prom_text_destroy(text);
}
END_TEST

START_TEST (text_add_byte_test) {
  int res;
  char *str;
  size_t sz;
  struct prom_text *text;

  mark_point();
  res = prom_text_add_byte(NULL, '"');
  ck_assert_msg(res < 0, "Failed to handle null text");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  text = prom_text_create(p);
  res = prom_text_add_byte(text, '{');
  ck_assert_msg(res == 0, "Failed to add byte: %s", strerror(errno));

  str = prom_text_get_str(p, text, &sz);
  ck_assert_msg(str != NULL, "Failed get text: %s", strerror(errno));
  ck_assert_msg(sz == 1, "Expected size 1, got %lu", (unsigned long) sz);
  ck_assert_msg(strcmp(str, "{") == 0, "Expected '{', got '%s'", str);

  prom_text_destroy(text);
}
END_TEST

START_TEST (text_add_str_test) {
  int res;
  char *str, *input;
  size_t sz;
  struct prom_text *text;

  mark_point();
  res = prom_text_add_str(NULL, NULL, 0);
  ck_assert_msg(res < 0, "Failed to handle null text");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  text = prom_text_create(p);
  res = prom_text_add_str(text, NULL, 0);
  ck_assert_msg(res < 0, "Failed to handle null str");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  input = "foobar";
  res = prom_text_add_str(text, input, 0);
  ck_assert_msg(res == 0, "Failed to handle zero-length text: %s",
    strerror(errno));

  str = prom_text_get_str(p, text, NULL);
  ck_assert_msg(str == NULL, "Failed to handle absent text");
  ck_assert_msg(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  mark_point();
  res = prom_text_add_str(text, input, strlen(input));
  ck_assert_msg(res == 0, "Failed to handle text: %s", strerror(errno));

  str = prom_text_get_str(p, text, &sz);
  ck_assert_msg(str != NULL, "Failed get text: %s", strerror(errno));
  ck_assert_msg(sz == 6, "Expected size 7, got %lu", (unsigned long) sz);
  ck_assert_msg(strcmp(str, input) == 0,
    "Expected '%s', got '%s'", input, str);

  prom_text_destroy(text);
}
END_TEST

START_TEST (text_from_labels_test) {
  const char *res, *expected;
  struct prom_text *text;
  pr_table_t *labels;

  mark_point();
  res = prom_text_from_labels(NULL, NULL, NULL);
  ck_assert_msg(res == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = prom_text_from_labels(p, NULL, NULL);
  ck_assert_msg(res == NULL, "Failed to handle null text");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  text = prom_text_create(p);
  res = prom_text_from_labels(p, text, NULL);
  ck_assert_msg(res != NULL, "Failed to handle null labels: %s",
    strerror(errno));
  ck_assert_msg(strcmp(res, "") == 0, "Expected '', got '%s'", res);

  /* Now, with labels. */
  mark_point();
  labels = pr_table_nalloc(p, 0, 2);
  res = prom_text_from_labels(p, text, labels);
  ck_assert_msg(res != NULL, "Failed to handle empty labels: %s",
    strerror(errno));
  ck_assert_msg(strcmp(res, "") == 0, "Expected '', got '%s'", res);

  mark_point();
  (void) pr_table_add_dup(labels, "protocol", "ftp", 0);
  (void) pr_table_add_dup(labels, "foo", "BAR", 0);
  res = prom_text_from_labels(p, text, labels);
  ck_assert_msg(res != NULL, "Failed to handle labels: %s", strerror(errno));

  expected = "{foo=\"BAR\",protocol=\"ftp\"}";
  ck_assert_msg(strcmp(res, expected) == 0,
    "Expected '%s', got '%s'", expected, res);

  prom_text_destroy(text);
}
END_TEST

Suite *tests_get_text_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("text");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, text_destroy_test);
  tcase_add_test(testcase, text_create_test);

  tcase_add_test(testcase, text_get_str_test);
  tcase_add_test(testcase, text_add_byte_test);
  tcase_add_test(testcase, text_add_str_test);

  tcase_add_test(testcase, text_from_labels_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
