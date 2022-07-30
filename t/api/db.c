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

/* Database API tests. */

#include "tests.h"
#include "prometheus/db.h"

static pool *p = NULL;

static const char *db_test_table = "/tmp/prt-mod_prometheus-db.dat";

static void set_up(void) {
  (void) unlink(db_test_table);

  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
    session.c = NULL;
    session.notes = NULL;
  }

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("prometheus.db", 1, 20);
  }

  mark_point();
  prom_db_init(p);
}

static void tear_down(void) {
  prom_db_free();

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("prometheus.db", 0, 0);
  }

  if (p != NULL) {
    destroy_pool(p);
    p = permanent_pool = NULL;
    session.c = NULL;
    session.notes = NULL;
  }

  (void) unlink(db_test_table);
}

START_TEST (db_close_test) {
  int res;

  mark_point();
  res = prom_db_close(NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);

  mark_point();
  res = prom_db_close(p, NULL);
  ck_assert_msg(res < 0, "Failed to handle null dbh");
  ck_assert_msg(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);
}
END_TEST

START_TEST (db_open_test) {
  int res;
  const char *table_path, *schema_name;
  struct prom_dbh *dbh;

  mark_point();
  dbh = prom_db_open(NULL, NULL, NULL);
  ck_assert_msg(dbh == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);

  mark_point();
  dbh = prom_db_open(p, NULL, NULL);
  ck_assert_msg(dbh == NULL, "Failed to handle null table path");
  ck_assert_msg(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);

  (void) unlink(db_test_table);
  table_path = db_test_table;
  schema_name = "prometheus_test";

  mark_point();
  dbh = prom_db_open(p, table_path, NULL);
  ck_assert_msg(dbh == NULL, "Failed to handle null schema name");
  ck_assert_msg(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);

  mark_point();
  dbh = prom_db_open(p, table_path, schema_name);
  ck_assert_msg(dbh != NULL, "Failed to open table '%s': %s", table_path,
    strerror(errno));

  mark_point();
  res = prom_db_close(p, dbh);
  ck_assert_msg(res == 0, "Failed to close table '%s': %s", table_path,
    strerror(errno));
  (void) unlink(db_test_table);
}
END_TEST

START_TEST (db_open_readonly_test) {
  int res;
  const char *table_path, *schema_name;
  struct prom_dbh *dbh;

  mark_point();
  dbh = prom_db_open_readonly(NULL, NULL, NULL);
  ck_assert_msg(dbh == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);

  mark_point();
  dbh = prom_db_open_readonly(p, NULL, NULL);
  ck_assert_msg(dbh == NULL, "Failed to handle null table path");
  ck_assert_msg(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);

  (void) unlink(db_test_table);
  table_path = db_test_table;
  schema_name = "prometheus_test";

  mark_point();
  dbh = prom_db_open_readonly(p, table_path, NULL);
  ck_assert_msg(dbh == NULL, "Failed to handle null schema name");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  dbh = prom_db_open_readonly(p, table_path, schema_name);
  ck_assert_msg(dbh == NULL, "Failed to handle missing table");
  ck_assert_msg(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  mark_point();
  dbh = prom_db_open(p, table_path, schema_name);
  ck_assert_msg(dbh != NULL,
    "Failed to open table '%s', schema '%s': %s", table_path, schema_name,
    strerror(errno));

  res = prom_db_close(p, dbh);
  ck_assert_msg(res == 0, "Failed to close database: %s", strerror(errno));

  mark_point();
  dbh = prom_db_open_readonly(p, table_path, schema_name);
  ck_assert_msg(dbh != NULL, "Failed to open table '%s': %s", table_path,
    strerror(errno));

  mark_point();
  res = prom_db_close(p, dbh);
  ck_assert_msg(res == 0, "Failed to close table '%s': %s", table_path,
    strerror(errno));
  (void) unlink(db_test_table);
}
END_TEST

START_TEST (db_open_with_version_test) {
  int res, flags = 0;
  struct prom_dbh *dbh;
  const char *table_path, *schema_name;
  unsigned int schema_version;

  mark_point();
  dbh = prom_db_open_with_version(NULL, NULL, NULL, 0, 0);
  ck_assert_msg(dbh == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);

  (void) unlink(db_test_table);
  table_path = db_test_table;
  schema_name = "prometheus_test";
  schema_version = 0;

  mark_point();
  dbh = prom_db_open_with_version(p, table_path, schema_name, schema_version,
    flags);
  ck_assert_msg(dbh != NULL,
    "Failed to open table '%s', schema '%s', version %u: %s", table_path,
    schema_name, schema_version, strerror(errno));

  res = prom_db_close(p, dbh);
  ck_assert_msg(res == 0, "Failed to close database: %s", strerror(errno));

  flags |= PROM_DB_OPEN_FL_INTEGRITY_CHECK;

  mark_point();
  dbh = prom_db_open_with_version(p, table_path, schema_name, schema_version,
    flags);
  ck_assert_msg(dbh != NULL,
    "Failed to open table '%s', schema '%s', version %u: %s", table_path,
    schema_name, schema_version, strerror(errno));

  res = prom_db_close(p, dbh);
  ck_assert_msg(res == 0, "Failed to close database: %s", strerror(errno));

  if (getenv("CI") == NULL &&
      getenv("TRAVIS") == NULL) {
    /* Enable the vacuuming for these tests. */
    flags |= PROM_DB_OPEN_FL_VACUUM;

    mark_point();
    dbh = prom_db_open_with_version(p, table_path, schema_name, schema_version,
      flags);
    ck_assert_msg(dbh != NULL,
      "Failed to open table '%s', schema '%s', version %u: %s", table_path,
      schema_name, schema_version, strerror(errno));

    res = prom_db_close(p, dbh);
    ck_assert_msg(res == 0, "Failed to close database: %s", strerror(errno));

    flags &= ~PROM_DB_OPEN_FL_VACUUM;
  }

  flags &= ~PROM_DB_OPEN_FL_INTEGRITY_CHECK;

  mark_point();
  schema_version = 76;
  flags |= PROM_DB_OPEN_FL_SCHEMA_VERSION_CHECK|PROM_DB_OPEN_FL_ERROR_ON_SCHEMA_VERSION_SKEW;
  dbh = prom_db_open_with_version(p, table_path, schema_name, schema_version,
    flags);
  ck_assert_msg(dbh == NULL, "Opened table with version skew unexpectedly");
  ck_assert_msg(errno == EPERM, "Expected EPERM (%d), got '%s' (%d)", EPERM,
    strerror(errno), errno);

  mark_point();
  flags &= ~PROM_DB_OPEN_FL_ERROR_ON_SCHEMA_VERSION_SKEW;
  dbh = prom_db_open_with_version(p, table_path, schema_name, schema_version,
    flags);
  ck_assert_msg(dbh != NULL,
    "Failed to open table '%s', schema '%s', version %u: %s", table_path,
    schema_name, schema_version, strerror(errno));

  res = prom_db_close(p, dbh);
  ck_assert_msg(res == 0, "Failed to close database: %s", strerror(errno));

  mark_point();
  schema_version = 76;
  dbh = prom_db_open_with_version(p, table_path, schema_name, schema_version,
    flags);
  ck_assert_msg(dbh != NULL,
    "Failed to open table '%s', schema '%s', version %u: %s", table_path,
    schema_name, schema_version, strerror(errno));

  res = prom_db_close(p, dbh);
  ck_assert_msg(res == 0, "Failed to close databas: %s", strerror(errno));

  mark_point();
  schema_version = 99;
  dbh = prom_db_open_with_version(p, table_path, schema_name, schema_version,
    flags);
  ck_assert_msg(dbh != NULL,
    "Failed to open table '%s', schema '%s', version %u: %s", table_path,
    schema_name, schema_version, strerror(errno));

  res = prom_db_close(p, dbh);
  ck_assert_msg(res == 0, "Failed to close database: %s", strerror(errno));

  (void) unlink(db_test_table);
}
END_TEST

START_TEST (db_open_readonly_with_version_test) {
  int res, flags = 0;
  struct prom_dbh *dbh;
  const char *table_path, *schema_name;
  unsigned int schema_version;

  mark_point();
  dbh = prom_db_open_readonly_with_version(NULL, NULL, NULL, 0, 0);
  ck_assert_msg(dbh == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Failed to set errno to EINVAL, got %s (%d)",
    strerror(errno), errno);

  (void) unlink(db_test_table);
  table_path = db_test_table;
  schema_name = "prometheus_test";
  schema_version = 0;

  mark_point();
  dbh = prom_db_open_with_version(p, table_path, schema_name, schema_version,
    flags);
  ck_assert_msg(dbh != NULL,
    "Failed to open table '%s', schema '%s', version %u: %s", table_path,
    schema_name, schema_version, strerror(errno));

  res = prom_db_close(p, dbh);
  ck_assert_msg(res == 0, "Failed to close database: %s", strerror(errno));

  mark_point();
  dbh = prom_db_open_readonly_with_version(p, table_path, schema_name,
    schema_version, flags);
  ck_assert_msg(dbh != NULL,
    "Failed to open table '%s', schema '%s', version %u: %s", table_path,
    schema_name, schema_version, strerror(errno));

  res = prom_db_close(p, dbh);
  ck_assert_msg(res == 0, "Failed to close database: %s", strerror(errno));

  flags |= PROM_DB_OPEN_FL_INTEGRITY_CHECK;

  mark_point();
  dbh = prom_db_open_readonly_with_version(p, table_path, schema_name,
    schema_version, flags);
  ck_assert_msg(dbh != NULL,
    "Failed to open table '%s', schema '%s', version %u: %s", table_path,
    schema_name, schema_version, strerror(errno));

  res = prom_db_close(p, dbh);
  ck_assert_msg(res == 0, "Failed to close database: %s", strerror(errno));

  if (getenv("CI") == NULL &&
      getenv("TRAVIS") == NULL) {
    /* Enable the vacuuming for these tests. */
    flags |= PROM_DB_OPEN_FL_VACUUM;

    mark_point();
    dbh = prom_db_open_readonly_with_version(p, table_path, schema_name,
      schema_version, flags);
    ck_assert_msg(dbh != NULL,
      "Failed to open table '%s', schema '%s', version %u: %s", table_path,
      schema_name, schema_version, strerror(errno));

    res = prom_db_close(p, dbh);
    ck_assert_msg(res == 0, "Failed to close database: %s", strerror(errno));

    flags &= ~PROM_DB_OPEN_FL_VACUUM;
  }

  flags &= ~PROM_DB_OPEN_FL_INTEGRITY_CHECK;

  mark_point();
  schema_version = 76;
  flags |= PROM_DB_OPEN_FL_SCHEMA_VERSION_CHECK|PROM_DB_OPEN_FL_ERROR_ON_SCHEMA_VERSION_SKEW;
  dbh = prom_db_open_readonly_with_version(p, table_path, schema_name,
    schema_version, flags);
  ck_assert_msg(dbh == NULL, "Opened table with version skew unexpectedly");
  ck_assert_msg(errno == EPERM, "Expected EPERM (%d), got '%s' (%d)", EPERM,
    strerror(errno), errno);

  mark_point();
  flags &= ~PROM_DB_OPEN_FL_ERROR_ON_SCHEMA_VERSION_SKEW;
  dbh = prom_db_open_readonly_with_version(p, table_path, schema_name,
    schema_version, flags);
  ck_assert_msg(dbh != NULL,
    "Failed to open table '%s', schema '%s', version %u: %s", table_path,
    schema_name, schema_version, strerror(errno));

  res = prom_db_close(p, dbh);
  ck_assert_msg(res == 0, "Failed to close database: %s", strerror(errno));

  mark_point();
  schema_version = 76;
  dbh = prom_db_open_readonly_with_version(p, table_path, schema_name,
    schema_version, flags);
  ck_assert_msg(dbh != NULL,
    "Failed to open table '%s', schema '%s', version %u: %s", table_path,
    schema_name, schema_version, strerror(errno));

  res = prom_db_close(p, dbh);
  ck_assert_msg(res == 0, "Failed to close databas: %s", strerror(errno));

  mark_point();
  schema_version = 99;
  dbh = prom_db_open_readonly_with_version(p, table_path, schema_name,
    schema_version, flags);
  ck_assert_msg(dbh != NULL,
    "Failed to open table '%s', schema '%s', version %u: %s", table_path,
    schema_name, schema_version, strerror(errno));

  res = prom_db_close(p, dbh);
  ck_assert_msg(res == 0, "Failed to close database: %s", strerror(errno));

  (void) unlink(db_test_table);
}
END_TEST

START_TEST (db_exec_stmt_test) {
  int res;
  const char *table_path, *schema_name, *stmt, *errstr;
  struct prom_dbh *dbh;

  mark_point();
  res = prom_db_exec_stmt(NULL, NULL, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = prom_db_exec_stmt(p, NULL, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle null dbh");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  (void) unlink(db_test_table);
  table_path = db_test_table;
  schema_name = "prometheus_test";

  mark_point();
  dbh = prom_db_open(p, table_path, schema_name);
  ck_assert_msg(dbh != NULL, "Failed to open table '%s': %s", table_path,
    strerror(errno));

  mark_point();
  res = prom_db_exec_stmt(p, dbh, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle null statement");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  stmt = "SELECT COUNT(*) FROM foo;";
  errstr = NULL;
  res = prom_db_exec_stmt(p, dbh, stmt, &errstr);
  ck_assert_msg(res < 0, "Failed to execute statement '%s'", stmt);
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = prom_db_close(p, dbh);
  ck_assert_msg(res == 0, "Failed to close database: %s", strerror(errno));

  (void) unlink(db_test_table);
}
END_TEST

static int create_table(pool *stmt_pool, struct prom_dbh *dbh,
    const char *table_name) {
  int res;
  const char *stmt, *errstr = NULL;

  stmt = pstrcat(stmt_pool, "CREATE TABLE ", table_name,
    " (id INTEGER, name TEXT);", NULL);
  res = prom_db_exec_stmt(stmt_pool, dbh, stmt, &errstr);
  return res;
}

START_TEST (db_prepare_stmt_test) {
  int res;
  const char *table_path, *schema_name, *stmt;
  struct prom_dbh *dbh;

  mark_point();
  res = prom_db_prepare_stmt(NULL, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = prom_db_prepare_stmt(p, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle null dbh");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  (void) unlink(db_test_table);
  table_path = db_test_table;
  schema_name = "prometheus_test";

  mark_point();
  dbh = prom_db_open(p, table_path, schema_name);
  ck_assert_msg(dbh != NULL, "Failed to open table '%s': %s", table_path,
    strerror(errno));

  mark_point();
  res = prom_db_prepare_stmt(p, dbh, NULL);
  ck_assert_msg(res < 0, "Failed to handle null statement");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  stmt = "foo bar baz?";
  res = prom_db_prepare_stmt(p, dbh, stmt);
  ck_assert_msg(res < 0, "Prepared invalid statement '%s' unexpectedly", stmt);
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  res = create_table(p, dbh, "foo");
  ck_assert_msg(res == 0, "Failed to create table 'foo': %s", strerror(errno));

  mark_point();
  stmt = "SELECT COUNT(*) FROM foo;";
  res = prom_db_prepare_stmt(p, dbh, stmt);
  ck_assert_msg(res == 0, "Failed to prepare statement '%s': %s", stmt,
    strerror(errno));

  mark_point();
  res = prom_db_finish_stmt(p, dbh, stmt);
  ck_assert_msg(res == 0, "Failed to finish statement '%s': %s", stmt,
    strerror(errno));

  res = create_table(p, dbh, "bar");
  ck_assert_msg(res == 0, "Failed to create table 'bar': %s", strerror(errno));

  mark_point();
  stmt = "SELECT COUNT(*) FROM bar;";
  res = prom_db_prepare_stmt(p, dbh, stmt);
  ck_assert_msg(res == 0, "Failed to prepare statement '%s': %s", stmt,
    strerror(errno));

  res = prom_db_close(p, dbh);
  ck_assert_msg(res == 0, "Failed to close database: %s", strerror(errno));

  (void) unlink(db_test_table);
}
END_TEST

START_TEST (db_finish_stmt_test) {
  int res;
  const char *table_path, *schema_name, *stmt;
  struct prom_dbh *dbh;

  mark_point();
  res = prom_db_finish_stmt(NULL, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle null arguments");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = prom_db_finish_stmt(p, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle null dbh");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  (void) unlink(db_test_table);
  table_path = db_test_table;
  schema_name = "prometheus_test";

  mark_point();
  dbh = prom_db_open(p, table_path, schema_name);
  ck_assert_msg(dbh != NULL, "Failed to open table '%s': %s", table_path,
    strerror(errno));

  mark_point();
  res = prom_db_finish_stmt(p, dbh, NULL);
  ck_assert_msg(res < 0, "Failed to handle null statement");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  stmt = "SELECT COUNT(*) FROM foo";
  res = prom_db_finish_stmt(p, dbh, stmt);
  ck_assert_msg(res < 0, "Failed to handle unprepared statement");
  ck_assert_msg(errno == ENOENT, "Expected ENOENT (%d), got '%s' (%d)", ENOENT,
    strerror(errno), errno);

  res = create_table(p, dbh, "foo");
  ck_assert_msg(res == 0, "Failed to create table 'foo': %s", strerror(errno));

  mark_point();
  res = prom_db_prepare_stmt(p, dbh, stmt);
  ck_assert_msg(res == 0, "Failed to prepare statement '%s': %s", stmt,
    strerror(errno));

  mark_point();
  res = prom_db_finish_stmt(p, dbh, stmt);
  ck_assert_msg(res == 0, "Failed to finish statement '%s': %s", stmt,
    strerror(errno));

  mark_point();
  res = prom_db_finish_stmt(p, dbh, stmt);
  ck_assert_msg(res < 0, "Failed to handle unprepared statement");
  ck_assert_msg(errno == ENOENT, "Expected ENOENT (%d), got '%s' (%d)", ENOENT,
    strerror(errno), errno);

  res = prom_db_close(p, dbh);
  ck_assert_msg(res == 0, "Failed to close database: %s", strerror(errno));

  (void) unlink(db_test_table);
}
END_TEST

START_TEST (db_bind_stmt_test) {
  int res;
  const char *table_path, *schema_name, *stmt;
  struct prom_dbh *dbh;
  int idx, int_val;
  long long_val;
  double double_val;
  char *text_val;

  mark_point();
  res = prom_db_bind_stmt(NULL, NULL, NULL, -1, -1, NULL);
  ck_assert_msg(res < 0, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = prom_db_bind_stmt(p, NULL, NULL, -1, -1, NULL);
  ck_assert_msg(res < 0, "Failed to handle null dbh");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  (void) unlink(db_test_table);
  table_path = db_test_table;
  schema_name = "prometheus_test";

  mark_point();
  dbh = prom_db_open(p, table_path, schema_name);
  ck_assert_msg(dbh != NULL, "Failed to open table '%s': %s", table_path,
    strerror(errno));

  mark_point();
  res = prom_db_bind_stmt(p, dbh, NULL, -1, -1, NULL);
  ck_assert_msg(res < 0, "Failed to handle null statement");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  stmt = "SELECT COUNT(*) FROM table";
  idx = -1;
  res = prom_db_bind_stmt(p, dbh, stmt, idx, PROM_DB_BIND_TYPE_INT, NULL);
  ck_assert_msg(res < 0, "Failed to handle invalid index %d", idx);
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  idx = 1;
  res = prom_db_bind_stmt(p, dbh, stmt, idx, PROM_DB_BIND_TYPE_INT, NULL);
  ck_assert_msg(res < 0, "Failed to handle unprepared statement");
  ck_assert_msg(errno == ENOENT, "Expected ENOENT (%d), got '%s' (%d)", ENOENT,
    strerror(errno), errno);

  res = create_table(p, dbh, "foo");
  ck_assert_msg(res == 0, "Failed to create table 'foo': %s", strerror(errno));

  mark_point();
  stmt = "SELECT COUNT(*) FROM foo;";
  res = prom_db_prepare_stmt(p, dbh, stmt);
  ck_assert_msg(res == 0, "Failed to prepare statement '%s': %s", stmt,
    strerror(errno));

  mark_point();
  res = prom_db_bind_stmt(p, dbh, stmt, idx, PROM_DB_BIND_TYPE_INT, NULL);
  ck_assert_msg(res < 0, "Failed to handle missing INT value");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  int_val = 7;
  res = prom_db_bind_stmt(p, dbh, stmt, idx, PROM_DB_BIND_TYPE_INT, &int_val);
  ck_assert_msg(res < 0, "Failed to handle invalid index value");
  ck_assert_msg(errno == EPERM, "Expected EPERM (%d), got '%s' (%d)", EPERM,
    strerror(errno), errno);

  mark_point();
  res = prom_db_bind_stmt(p, dbh, stmt, idx, PROM_DB_BIND_TYPE_LONG, NULL);
  ck_assert_msg(res < 0, "Failed to handle missing LONG value");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  long_val = 7;
  res = prom_db_bind_stmt(p, dbh, stmt, idx, PROM_DB_BIND_TYPE_LONG,
    &long_val);
  ck_assert_msg(res < 0, "Failed to handle invalid index value");
  ck_assert_msg(errno == EPERM, "Expected EPERM (%d), got '%s' (%d)", EPERM,
    strerror(errno), errno);

  mark_point();
  double_val = 7.0;
  res = prom_db_bind_stmt(p, dbh, stmt, idx, PROM_DB_BIND_TYPE_DOUBLE,
    &double_val);
  ck_assert_msg(res < 0, "Failed to handle invalid index value");
  ck_assert_msg(errno == EPERM, "Expected EPERM (%d), got '%s' (%d)", EPERM,
    strerror(errno), errno);

  mark_point();
  res = prom_db_bind_stmt(p, dbh, stmt, idx, PROM_DB_BIND_TYPE_TEXT, NULL);
  ck_assert_msg(res < 0, "Failed to handle missing TEXT value");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  text_val = "testing";
  res = prom_db_bind_stmt(p, dbh, stmt, idx, PROM_DB_BIND_TYPE_TEXT, text_val);
  ck_assert_msg(res < 0, "Failed to handle invalid index value");
  ck_assert_msg(errno == EPERM, "Expected EPERM (%d), got '%s' (%d)", EPERM,
    strerror(errno), errno);

  mark_point();
  res = prom_db_bind_stmt(p, dbh, stmt, idx, PROM_DB_BIND_TYPE_NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle invalid NULL value");
  ck_assert_msg(errno == EPERM, "Expected EPERM (%d), got '%s' (%d)", EPERM,
    strerror(errno), errno);

  mark_point();
  stmt = "SELECT COUNT(*) FROM foo WHERE id = ?;";
  res = prom_db_prepare_stmt(p, dbh, stmt);
  ck_assert_msg(res == 0, "Failed to prepare statement '%s': %s", stmt,
    strerror(errno));

  mark_point();
  int_val = 7;
  res = prom_db_bind_stmt(p, dbh, stmt, idx, PROM_DB_BIND_TYPE_INT, &int_val);
  ck_assert_msg(res == 0, "Failed to bind INT value: %s", strerror(errno));

  res = prom_db_close(p, dbh);
  ck_assert_msg(res == 0, "Failed to close database: %s", strerror(errno));

  (void) unlink(db_test_table);
}
END_TEST

START_TEST (db_exec_prepared_stmt_test) {
  int res;
  array_header *results;
  const char *table_path, *schema_name, *stmt, *errstr = NULL;
  struct prom_dbh *dbh;

  mark_point();
  results = prom_db_exec_prepared_stmt(NULL, NULL, NULL, NULL);
  ck_assert_msg(results == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  results = prom_db_exec_prepared_stmt(p, NULL, NULL, NULL);
  ck_assert_msg(results == NULL, "Failed to handle null dbh");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  (void) unlink(db_test_table);
  table_path = db_test_table;
  schema_name = "prometheus_test";

  mark_point();
  dbh = prom_db_open(p, table_path, schema_name);
  ck_assert_msg(dbh != NULL, "Failed to open table '%s': %s", table_path,
    strerror(errno));

  mark_point();
  results = prom_db_exec_prepared_stmt(p, dbh, NULL, NULL);
  ck_assert_msg(results == NULL, "Failed to handle null statement");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  stmt = "SELECT COUNT(*) FROM foo;";
  results = prom_db_exec_prepared_stmt(p, dbh, stmt, &errstr);
  ck_assert_msg(results == NULL, "Failed to handle unprepared statement");
  ck_assert_msg(errno == ENOENT, "Expected ENOENT (%d), got '%s' (%d)", ENOENT,
    strerror(errno), errno);

  res = create_table(p, dbh, "foo");
  ck_assert_msg(res == 0, "Failed to create table 'foo': %s", strerror(errno));

  mark_point();
  res = prom_db_prepare_stmt(p, dbh, stmt);
  ck_assert_msg(res == 0, "Failed to prepare statement '%s': %s", stmt,
    strerror(errno));

  mark_point();
  results = prom_db_exec_prepared_stmt(p, dbh, stmt, &errstr);
  ck_assert_msg(results != NULL,
    "Failed to execute prepared statement '%s': %s (%s)", stmt, errstr,
    strerror(errno));

  res = prom_db_close(p, dbh);
  ck_assert_msg(res == 0, "Failed to close database: %s", strerror(errno));

  (void) unlink(db_test_table);
}
END_TEST

START_TEST (db_reindex_test) {
  int res;
  const char *table_path, *schema_name, *index_name, *errstr = NULL;
  struct prom_dbh *dbh;

  mark_point();
  res = prom_db_reindex(NULL, NULL, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = prom_db_reindex(p, NULL, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle null dbh");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  (void) unlink(db_test_table);
  table_path = db_test_table;
  schema_name = "prometheus_test";

  mark_point();
  dbh = prom_db_open(p, table_path, schema_name);
  ck_assert_msg(dbh != NULL, "Failed to open table '%s': %s", table_path,
    strerror(errno));

  mark_point();
  res = prom_db_reindex(p, dbh, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle null index name");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  index_name = "test_idx";
  res = prom_db_reindex(p, dbh, index_name, &errstr);
  ck_assert_msg(res < 0, "Failed to handle invalid index");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got '%s' (%d)", EINVAL,
    strerror(errno), errno);
  ck_assert_msg(errstr != NULL, "Failed to provide error string");

  res = prom_db_close(p, dbh);
  ck_assert_msg(res == 0, "Failed to close database: %s", strerror(errno));

  (void) unlink(db_test_table);
}
END_TEST

START_TEST (db_last_row_id_test) {
  int res;
  const char *table_path, *schema_name;
  int64_t row_id = 0;
  struct prom_dbh *dbh;

  mark_point();
  res = prom_db_last_row_id(NULL, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = prom_db_last_row_id(p, NULL, NULL);
  ck_assert_msg(res < 0, "Failed to handle null dbh");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  (void) unlink(db_test_table);
  table_path = db_test_table;
  schema_name = "prometheus_test";

  mark_point();
  dbh = prom_db_open(p, table_path, schema_name);
  ck_assert_msg(dbh != NULL, "Failed to open table '%s': %s", table_path,
    strerror(errno));

  mark_point();
  res = prom_db_last_row_id(p, dbh, NULL);
  ck_assert_msg(res < 0, "Failed to handle null row_id");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = prom_db_last_row_id(p, dbh, &row_id);
  ck_assert_msg(res == 0, "Failed to get last row ID: %s", strerror(errno));

  res = prom_db_close(p, dbh);
  ck_assert_msg(res == 0, "Failed to close database: %s", strerror(errno));

  (void) unlink(db_test_table);
}
END_TEST

Suite *tests_get_db_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("db");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, db_close_test);
  tcase_add_test(testcase, db_open_test);
  tcase_add_test(testcase, db_open_readonly_test);
  tcase_add_test(testcase, db_open_with_version_test);
  tcase_add_test(testcase, db_open_readonly_with_version_test);
  tcase_add_test(testcase, db_exec_stmt_test);
  tcase_add_test(testcase, db_prepare_stmt_test);
  tcase_add_test(testcase, db_finish_stmt_test);
  tcase_add_test(testcase, db_bind_stmt_test);
  tcase_add_test(testcase, db_exec_prepared_stmt_test);
  tcase_add_test(testcase, db_reindex_test);
  tcase_add_test(testcase, db_last_row_id_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
