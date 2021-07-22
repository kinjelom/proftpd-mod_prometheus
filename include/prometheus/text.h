/*
 * ProFTPD - mod_prometheus text API
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

#ifndef MOD_PROMETHEUS_TEXT_H
#define MOD_PROMETHEUS_TEXT_H

#include "mod_prometheus.h"
#include "prometheus/metric.h"

struct prom_text;

struct prom_text *prom_text_create(pool *p);
int prom_text_destroy(struct prom_text *text);

int prom_text_add_byte(struct prom_text *text, char ch);
int prom_text_add_str(struct prom_text *text, const char *str, size_t sz);

/* Obtain a copy of the accumulated text, duplicated from the given pool. */
char *prom_text_get_str(pool *p, struct prom_text *text, size_t *sz);

/* Convert the given labels to text. */
const char *prom_text_from_labels(pool *p, struct prom_text *text,
  pr_table_t *labels);

#endif /* MOD_PROMETHEUS_TEXT_H */
