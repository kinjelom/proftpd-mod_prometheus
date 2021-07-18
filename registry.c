/*
 * ProFTPD - mod_prometheus registry implementation
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
#include "registry.h"
#include "metric.h"

struct prom_metric *prom_registry_get_metric(pool *p, const char *metric_name) {
  if (p == NULL ||
      metric_name == NULL) {
    errno = EINVAL;
    return NULL;
  }

  errno = ENOSYS;
  return NULL;
}

/* Returns the text for all metrics in the registry. */
const char *prom_registry_get_text(pool *p) {
  errno = ENOSYS;
  return NULL;
}

int prom_registry_init(pool *p) {
  if (p == NULL) {
    errno = EINVAL;
    return -1;
  }

  errno = ENOSYS;
  return -1;
}

int prom_registry_free(void) {
  /* XXX Automatically frees metrics objects for all known metric IDs. */
  errno = ENOSYS;
  return -1;
}
