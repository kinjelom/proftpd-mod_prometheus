/*
 * ProFTPD - mod_prometheus text implementation
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
#include "prometheus/text.h"

struct prom_text {
  pool *pool;
  char *buf, *ptr;
  size_t bufsz, buflen;
};

#define PROM_TEXT_DEFAULT_BUFFER_SIZE	1024

static const char *trace_channel = "prometheus.text";

static void ensure_text_size(struct prom_text *text, size_t new_textsz) {
  char *buf, *ptr;
  size_t buflen;

  if (new_textsz <= text->bufsz) {
    /* Nothing to do. */
    return;
  }

  ptr = pcalloc(text->pool, new_textsz);
  memcpy(ptr, text->ptr, text->bufsz - text->buflen);
  buf = ptr + (text->buf - text->ptr);

  /* buflen is the remaining length of buffer.  So we add the increased buffer
   * size to the existing buflen to obtain the new remaining length.
   */
  buflen = text->buflen + (new_textsz - text->bufsz);

  text->bufsz = new_textsz;
  text->buf = buf;
  text->buflen = buflen;
  text->ptr = ptr;
}

int prom_text_add_byte(struct prom_text *text, char ch) {
  if (text == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (text->buflen == 0) {
    ensure_text_size(text, text->bufsz * 2);
  }

  pr_trace_msg(trace_channel, 19, "appending character (%c)", ch);
  *(text->buf++) = ch;
  text->buflen -= 1;

  return 0;
}

int prom_text_add_str(struct prom_text *text, const char *str, size_t sz) {
  register unsigned int i;

  if (text == NULL ||
      str == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (sz == 0) {
    return 0;
  }

  if (text->buflen < sz) {
    ensure_text_size(text, text->bufsz * 2);
  }

  pr_trace_msg(trace_channel, 19, "appending text '%.*s' (%lu)", (int) sz, str,
    (unsigned long) sz);
  for (i = 0; i < sz; i++) {
    *(text->buf++) = str[i];
  }
  text->buflen -= sz;

  return 0;
}

char *prom_text_get_str(pool *p, struct prom_text *text, size_t *sz) {
  char *str;

  if (p == NULL ||
      text == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (text->buflen == text->bufsz) {
    /* No textual data accumulated yet. */
    errno = ENOENT;
    return NULL;
  }

  str = pstrdup(p, text->ptr);
  if (sz != NULL) {
    *sz = text->buf - text->ptr;
  }

  return str;
}

static int label_keycmp(const void *a, const void *b) {
  return strcmp(*((char **) a), *((char **) b));
}

/* Note that format for the returned text is very specific.  And, for
 * consistency, we should always sort by key names.  Label tables ALWAYS
 * have strings for keys and values.  (If they don't, it's a code bug.)
 */
const char *prom_text_from_labels(pool *p, struct prom_text *text,
    pr_table_t *labels) {
  register unsigned int i;
  pool *tmp_pool;
  int key_count = 0;
  array_header *keys;
  const void *key;
  char **key_names, *label_text = NULL;

  if (p == NULL ||
      text == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (labels != NULL) {
    key_count = pr_table_count(labels);
  }

  if (key_count == 0) {
    return pstrdup(p, "");
  }

  tmp_pool = make_sub_pool(text->pool);

  /* First, get a list of keys, in sorted order. */
  keys = make_array(p, key_count, sizeof(char *));

  pr_table_rewind(labels);
  key = pr_table_next(labels);
  while (key != NULL) {
    pr_signals_handle();

    *((char **) push_array(keys)) = pstrdup(p, key);
    key = pr_table_next(labels);
  }

  qsort((void *) keys->elts, keys->nelts, sizeof(char *), label_keycmp);

  /* Now, start building up the textual data. */
  key_names = keys->elts;
  prom_text_add_byte(text, '{');
  for (i = 0; i < keys->nelts; i++) {
    size_t key_namesz, valsz;
    char *key_name;
    const void *val;

    if (i != 0) {
      prom_text_add_byte(text, ',');
    }

    key_name = key_names[i];
    key_namesz = strlen(key_name);
    prom_text_add_str(text, key_name, key_namesz);
    prom_text_add_byte(text, '=');
    prom_text_add_byte(text, '"');

    val = pr_table_get(labels, key_name, &valsz);

    /* Note that we _subtract_ one here, because tables store values as
     * opaque objects, and thus include the terminating NUL for text.  But
     * we do not want to include that NUL in our length calculations.
     */
    prom_text_add_str(text, val, valsz-1);

    prom_text_add_byte(text, '"');
  }
  prom_text_add_byte(text, '}');
  destroy_pool(tmp_pool);

  /* Finally, get our accumulated textual data. */
  label_text = prom_text_get_str(p, text, NULL);

  pr_trace_msg(trace_channel, 9, "converted labels to text '%s'", label_text);
  return label_text;
}

struct prom_text *prom_text_create(pool *p) {
  pool *text_pool;
  struct prom_text *text;

  if (p == NULL) {
    errno = EINVAL;
    return NULL;
  }

  text_pool = make_sub_pool(p);
  pr_pool_tag(text_pool, "Prometheus text pool");

  text = pcalloc(text_pool, sizeof(struct prom_text));
  text->pool = text_pool;
  text->bufsz = text->buflen = PROM_TEXT_DEFAULT_BUFFER_SIZE;
  text->ptr = text->buf = pcalloc(text->pool, text->bufsz);

  return text;
}

int prom_text_destroy(struct prom_text *text) {
  if (text == NULL) {
    errno = EINVAL;
    return -1;
  }

  destroy_pool(text->pool);
  return 0;
}
