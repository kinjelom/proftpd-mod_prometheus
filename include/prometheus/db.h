/*
 * ProFTPD - mod_prometheus database API
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

#ifndef MOD_PROMETHEUS_DB_H
#define MOD_PROMETHEUS_DB_H

#include "mod_prometheus.h"

struct prom_dbh;

int prom_db_init(pool *p);
int prom_db_free(void);

/* Create/prepare the database (with the given schema name) at the given path */
struct prom_dbh *prom_db_open(pool *p, const char *table_path,
  const char *schema_name);

/* Open the existing database (with the given schema name) at the given path. */
struct prom_dbh *prom_db_open_readonly(pool *p, const char *table_path,
  const char *schema_name);

/* Create/prepare the database (with the given schema name) at the given path.
 * If the database/schema already exists, check that its schema version is
 * greater than or equal to the given minimum version.  If not, delete that
 * database and create a new one.
 */
struct prom_dbh *prom_db_open_with_version(pool *p, const char *table_path,
  const char *schema_name, unsigned int schema_version, int flags);
#define PROM_DB_OPEN_FL_SCHEMA_VERSION_CHECK		0x001
#define PROM_DB_OPEN_FL_ERROR_ON_SCHEMA_VERSION_SKEW	0x002
#define PROM_DB_OPEN_FL_INTEGRITY_CHECK			0x004
#define PROM_DB_OPEN_FL_VACUUM				0x008
#define PROM_DB_OPEN_FL_SKIP_VACUUM			0x010

/* Open the existing database (with the given schema name) at the given path.
 * If the database/schema already exists, check that its schema version is
 * greater than or equal to the given minimum version.
 */
struct prom_dbh *prom_db_open_readonly_with_version(pool *p,
  const char *table_path, const char *schema_name, unsigned int schema_version,
  int flags);

/* Close the database. */
int prom_db_close(pool *p, struct prom_dbh *dbh);

int prom_db_prepare_stmt(pool *p, struct prom_dbh *dbh, const char *stmt);
int prom_db_finish_stmt(pool *p, struct prom_dbh *dbh, const char *stmt);
int prom_db_bind_stmt(pool *p, struct prom_dbh *dbh, const char *stmt, int idx,
  int type, void *data);
#define PROM_DB_BIND_TYPE_INT		1
#define PROM_DB_BIND_TYPE_LONG		2
#define PROM_DB_BIND_TYPE_DOUBLE	3
#define PROM_DB_BIND_TYPE_TEXT		4
#define PROM_DB_BIND_TYPE_NULL		5

/* Executes the given statement.  Assumes that the caller is not using a SELECT,
 * and/or is uninterested in the statement results.
 */
int prom_db_exec_stmt(pool *p, struct prom_dbh *dbh, const char *stmt,
  const char **errstr);

/* Executes the given statement as a previously prepared statement. */
array_header *prom_db_exec_prepared_stmt(pool *p, struct prom_dbh *dbh,
  const char *stmt, const char **errstr);

/* Rebuild the named index. */
int prom_db_reindex(pool *p, struct prom_dbh *dbh,
  const char *index_name, const char **errstr);

/* Obtain the ROWID for the last inserted row. */
int prom_db_last_row_id(pool *p, struct prom_dbh *dbh, int64_t *row_id);

#endif /* MOD_PROMETHEUS_DB_H */
