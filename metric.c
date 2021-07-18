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
#include "metric.h"

static const char *metric_prefix = "proftpd_";

static const char *trace_channel = "prometheus.metric";

/* Returns the text for the specified metric ID. */
const char *prom_metric_get_text(pool *p, struct prom_metric *metric) {
  if (p == NULL ||
      metric == NULL) {
    errno = EINVAL;
    return NULL;
  }

  errno = ENOSYS;
  return NULL;
}

/* Increment the specified metric ID. */
int prom_metric_incr_value(pool *p, struct prom_metric *metric,
    int32_t incr, pr_table_t *labels) {
  if (p == NULL ||
      metric == NULL) {
    errno = EINVAL;
    return -1;
  }

  errno = ENOSYS;
  return -1;
}

struct prom_metric *prom_metric_alloc(pool *p, const char *name) {
  if (p == NULL ||
      name == NULL) {
    errno = EINVAL;
    return NULL;
  }

  errno = ENOSYS;
  return NULL;
}

int prom_metric_destroy(pool *p, struct prom_metric *metric) {
  if (metric == NULL) {
    errno = EINVAL;
    return -1;
  }

  errno = ENOSYS;
  return -1;
}

int prom_metric_init(pool *p) {
  /* XXX Automatically instantiates metrics objects for all known metric
   * names, * modulo loaded modules (mod_sftp, mod_ban, mod_tls, etc).
   * Registers them in the registry.
   */

/* XXX Once all metrics have been created, registered, call
 * prom_registry_sort_metrics().
 *
 * Why?  We ideally want to return all metrics in sorted order, every time
 * we are scraped.  So doing a one-time ordering of the list/keys is best.
 * Plus it will help with lookups.
 */

  errno = ENOSYS;
  return -1;
}

int prom_metric_free(void) {
  return 0;
}
