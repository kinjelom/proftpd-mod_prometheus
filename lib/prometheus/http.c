/*
 * ProFTPD - mod_prometheus http implementation
 * Copyright (c) 2021-2024 TJ Saunders
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
#include "prometheus/http.h"

#if defined(HAVE_ZLIB_H)
# include <zlib.h>

/* RFC 1952 Section 2.3 defines the gzip header:
 *
 * +---+---+---+---+---+---+---+---+---+---+
 * |ID1|ID2|CM |FLG|     MTIME     |XFL|OS |
 * +---+---+---+---+---+---+---+---+---+---+
 */
static gz_header gzip_header = {
  TRUE, 					/* is text? */
  0,    					/* modification time */
  0,    					/* flags */
  0,    					/* os */
  NULL, 					/* extra */
  0,
  0,
  NULL, 					/* name */
  0,
  (unsigned char *) MOD_PROMETHEUS_VERSION,	/* comment */
  0,
  TRUE,						/* header CRC */
  0
};
#endif /* HAVE_ZLIB_H */

/* Per libmicrohttpd docs, we should define this after we have our system
 * headers, but before including `microhttpd.h`.
 */
#define MHD_PLATFORM_H	1
#include <microhttpd.h>

#if MHD_VERSION < 0x00097002
/* Prior to this change, the library used only `int`, not `enum MHD_Result`.
 * So to avoid compiler warnings for older library versions (such as those
 * provided by Centos), we need to jump through preprocessor hoops.
 */
# undef MHD_YES
# undef MHD_NO
enum MHD_Result {
  /* MHD result code for "NO". */
  MHD_NO = 0,

  /* MHD result code for "YES". */
  MHD_YES = 1
};
#endif /* # MHD_VERSION older than 0x00097002 */

struct prom_http {
  pool *pool;
  struct prom_registry *registry;
  struct MHD_Daemon *mhd;
};

/* HTTP Basic Auth settings. */
static const char *http_realm = "proftpd";
static const char *http_username = NULL;
static const char *http_password = NULL;

static const char *trace_channel = "prometheus.http";
static const char *clf_channel = "prometheus.http.clf";

static void log_cb(void *user_data, const char *fmt, va_list msg) {
  pr_trace_vmsg(trace_channel, 7, fmt, msg);
}

static void panic_cb(void *user_data, const char *file, unsigned int lineno,
    const char *reason) {
  (void) pr_log_writefile(prometheus_logfd, MOD_PROMETHEUS_VERSION,
    "microhttpd panic: [%s:%u] %s", file, lineno, reason);
}

static int can_gzip(struct MHD_Connection *conn) {
#if defined(HAVE_ZLIB_H)
  const char *accept_encoding, *gzip_encoding = NULL;

  accept_encoding = MHD_lookup_connection_value(conn, MHD_HEADER_KIND,
    MHD_HTTP_HEADER_ACCEPT_ENCODING);
  if (accept_encoding == NULL) {
    return FALSE;
  }

  pr_trace_msg(trace_channel, 19, "found Accept-Encoding request header: '%s'",
    accept_encoding);

  if (strcmp(accept_encoding, "*") == 0) {
    return TRUE;
  }

  gzip_encoding = strstr(accept_encoding, "gzip");
  if (gzip_encoding == NULL) {
    return FALSE;
  }

  if ((gzip_encoding == accept_encoding ||
       gzip_encoding[-1] == ',' ||
       gzip_encoding[-1] == ' ') &&
      (gzip_encoding[4] == '\0' ||
       gzip_encoding[4] == ',' ||
       gzip_encoding[4] == ';')) {
    return TRUE;
  }
#endif /* HAVE_ZLIB_H */

  return FALSE;
}

#if defined(HAVE_ZLIB_H)
static const char *zlib_strerror(int zerrno) {
  const char *zstr = "unknown";

  switch (zerrno) {
    case Z_OK:
      zstr = "OK";
      break;

    case Z_STREAM_END:
      return "End of stream";
      break;

    case Z_STREAM_ERROR:
      return "Stream error";
      break;

    case Z_NEED_DICT:
      return "Need dictionary";
      break;

    case Z_ERRNO:
      zstr = strerror(errno);
      break;

    case Z_DATA_ERROR:
      zstr = "Data error";
      break;

    case Z_MEM_ERROR:
      zstr = "Memory error";
      break;

    case Z_BUF_ERROR:
      zstr = "Buffer error";
      break;

    case Z_VERSION_ERROR:
      zstr = "Version error";
      break;
  }

  return zstr;
}
#endif /* HAVE_ZLIB_H */

static const char *gzip_text(pool *p, const char *text, size_t text_len,
    size_t *gzipped_textlen) {
#if defined(HAVE_ZLIB_H)
  int res;
  z_stream *zstrm;
  unsigned char *output_buf = NULL;
  const char *gzipped_text = NULL;

  zstrm = pcalloc(p, sizeof(z_stream));
  zstrm->zalloc = Z_NULL;
  zstrm->zfree = Z_NULL;
  zstrm->opaque = Z_NULL;

  zstrm->next_in = (Bytef *) text;
  zstrm->avail_in = zstrm->total_in = text_len;

  /* It's possible that it may require more room to compress the given
   * text, especially if it's small.  Be prepared.
   */
  zstrm->avail_out = zstrm->total_out = (text_len * 3);
  zstrm->next_out = output_buf = pcalloc(p, zstrm->avail_out);

  /* Note that it is IMPORTANT that the `windowBits` value be 31 or more here,
   * to indicate to zlib that it should add a gzip header.  Subtle magic.
   */
  res = deflateInit2(zstrm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 31, 8,
    Z_DEFAULT_STRATEGY);
  if (res != Z_OK) {
    deflateEnd(zstrm);
    pr_trace_msg(trace_channel, 1,
      "error initializing zlib for deflation: %s (%d)",
      zstrm->msg ? zstrm->msg : zlib_strerror(res), res);
    return NULL;
  }

  res = deflateSetHeader(zstrm, &gzip_header);
  if (res != Z_OK) {
    deflateEnd(zstrm);
    pr_trace_msg(trace_channel, 1, "error setting gzip header: %s (%d)",
      zstrm->msg ? zstrm->msg : zlib_strerror(res), res);
    return NULL;
  }

  res = deflate(zstrm, Z_FINISH);
  if (res != Z_STREAM_END) {
    deflateEnd(zstrm);
    pr_trace_msg(trace_channel, 1, "error compressing data: %s",
      zstrm->msg ? zstrm->msg : zlib_strerror(res));
    return NULL;
  }

  pr_trace_msg(trace_channel, 19, "available compressed text: %lu bytes",
    (unsigned long) zstrm->total_out);
  *gzipped_textlen = zstrm->total_out;
  gzipped_text = pcalloc(p, *gzipped_textlen);
  memcpy((char *) gzipped_text, output_buf, *gzipped_textlen);

  deflateEnd(zstrm);
  return gzipped_text;
#endif /* HAVE_ZLIB_H */

  errno = ENOSYS;
  return NULL;
}

static const char *get_ip_text(pool *p, const struct sockaddr *sa) {
  char *remote_ip;
#if defined(PR_USE_IPV6)
  size_t remote_iplen = INET6_ADDRSTRLEN;
#else
  size_t remote_iplen = INET_ADDRSTRLEN;
#endif /* PR_USE_IPV6 */

  remote_ip = pcalloc(p, remote_iplen);

  switch (sa->sa_family) {
    case AF_INET: {
      struct sockaddr_in *sin;

      sin = (struct sockaddr_in *) sa;
      pr_inet_ntop(AF_INET, &(sin->sin_addr), remote_ip, remote_iplen - 1);
      break;
    }

#if defined(PR_USE_IPV6)
    case AF_INET6: {
      struct sockaddr_in6 *sin6;

      sin6 = (struct sockaddr_in6 *) sa;
      pr_inet_ntop(AF_INET6, &(sin6->sin6_addr), remote_ip, remote_iplen - 1);
      break;
    }
#endif /* PR_USE_IPV6 */

    default:
      snprintf(remote_ip, remote_iplen-1, "%s", "unknown");
      break;
  }

  return remote_ip;
}

static void log_clf(pool *p, struct MHD_Connection *conn, const char *username,
    const char *http_method, const char *http_uri, const char *http_version,
    unsigned int status_code, size_t resplen) {
  int clf_level = 1, res;
  const union MHD_ConnectionInfo *conn_info = NULL;
  const char *remote_ip = NULL;
  char timestamp[128];
  struct tm *tm;
  time_t now;

  res = pr_trace_get_level(clf_channel);
  if (res < clf_level) {
    return;
  }

  now = time(NULL);
  tm = pr_gmtime(p, &now);
  if (tm == NULL) {
    return;
  }

  conn_info = MHD_get_connection_info(conn, MHD_CONNECTION_INFO_CLIENT_ADDRESS,
    NULL);
  if (username == NULL) {
    username = "-";
  }

  remote_ip = get_ip_text(p, conn_info->client_addr);

  memset(timestamp, '\0', sizeof(timestamp));
  strftime(timestamp, sizeof(timestamp)-1, "%d/%b/%Y:%H:%M:%S %z", tm);

  pr_trace_msg(clf_channel, clf_level, "%s - %s [%s] \"%s %s %s\" %u %lu",
    remote_ip, username, timestamp, http_method, http_uri, http_version,
    status_code, (unsigned long) resplen);
}

#if MHD_VERSION < 0x00097002
static int handle_request_cb(void *user_data,
    struct MHD_Connection *conn, const char *http_uri, const char *http_method,
    const char *http_version, const char *request_body, size_t *request_bodysz,
    void **conn_user_data) {
#else
static enum MHD_Result handle_request_cb(void *user_data,
    struct MHD_Connection *conn, const char *http_uri, const char *http_method,
    const char *http_version, const char *request_body, size_t *request_bodysz,
    void **conn_user_data) {
#endif
  struct prom_http *http;
  pool *resp_pool;
  unsigned int status_code;
  const char *text;
  size_t textlen;
  struct MHD_Response *resp = NULL;
  int res;

  http = user_data;
  resp_pool = make_sub_pool(http->pool);
  pr_pool_tag(resp_pool, "Prometheus response pool");

  if (strcmp(http_method, "GET") != 0) {
    status_code = MHD_HTTP_METHOD_NOT_ALLOWED;
    text = "Method Not Allowed\n";
    textlen = strlen(text);

    resp = MHD_create_response_from_buffer(textlen, (void *) text,
      MHD_RESPMEM_PERSISTENT);
    (void) MHD_add_response_header(resp, MHD_HTTP_HEADER_CONTENT_TYPE,
      "text/plain");
    res = MHD_queue_response(conn, status_code, resp);
    MHD_destroy_response(resp);

    log_clf(resp_pool, conn, NULL, http_method, http_uri, http_version,
      status_code, textlen);
    destroy_pool(resp_pool);

    return res;
  }

  if (strcmp(http_uri, "/") == 0) {
    status_code = MHD_HTTP_OK;
    text = "OK\n";
    textlen = strlen(text);

    resp = MHD_create_response_from_buffer(textlen, (void *) text,
      MHD_RESPMEM_PERSISTENT);
    (void) MHD_add_response_header(resp, MHD_HTTP_HEADER_CONTENT_TYPE,
      "text/plain");
    res = MHD_queue_response(conn, status_code, resp);
    MHD_destroy_response(resp);

    log_clf(resp_pool, conn, NULL, http_method, http_uri, http_version,
      status_code, textlen);
    destroy_pool(resp_pool);

    return res;
  }

  if (strcmp(http_uri, "/metrics") == 0) {
    int xerrno, use_gzip = FALSE;
    char *request_username = NULL;

    if (http_username != NULL) {
      char *request_password = NULL;
      int auth_failed = TRUE;

      pr_trace_msg(trace_channel, 19,
        "exporter received /metrics request, validating basic auth");

      request_username = MHD_basic_auth_get_username_password(conn,
        &request_password);

      if (request_username == NULL) {
        pr_trace_msg(trace_channel, 19,
          "/metrics request lacks required credentials, rejecting");
        auth_failed = TRUE;

      } else {
        if (strcmp(request_username, http_username) == 0) {
          if (strcmp(request_password, http_password) == 0) {
            char *ptr;

            /* Authenticated. */
            auth_failed = FALSE;
            pr_trace_msg(trace_channel, 19,
              "/metrics request from '%s' validated", request_username);

            /* Free the username memory from libmicrohttpd, but keep a
             * copy for ourselves, for CLF logging, first.
             */
            ptr = request_username;
            request_username = pstrdup(resp_pool, ptr);
            free(ptr);

          } else {
            /* Wrong password. */
            pr_trace_msg(trace_channel, 19,
              "/metrics request from '%s' used wrong password, rejecting",
              request_username);
            auth_failed = TRUE;
          }

        } else {
          /* Wrong username. */
          pr_trace_msg(trace_channel, 19,
            "/metrics request used wrong username '%s', rejecting",
            request_username);
          auth_failed = TRUE;
        }
      }

      if (request_password != NULL) {
        free(request_password);
        request_password = NULL;
      }

      if (auth_failed == TRUE) {
        text = "Authentication required\n";
        textlen = strlen(text);
        status_code = MHD_HTTP_UNAUTHORIZED;

        resp = MHD_create_response_from_buffer(textlen, (void *) text,
          MHD_RESPMEM_PERSISTENT);
        (void) MHD_add_response_header(resp, MHD_HTTP_HEADER_CONTENT_TYPE,
          "text/plain");
        res = MHD_queue_basic_auth_fail_response(conn, http_realm, resp);
        MHD_destroy_response(resp);

        log_clf(resp_pool, conn, request_username, http_method, http_uri,
          http_version, status_code, textlen);
        destroy_pool(resp_pool);

        return res;
      }

    } else {
      pr_trace_msg(trace_channel, 19, "exporter received /metrics request");
    }

    text = prom_registry_get_text(resp_pool, http->registry);
    xerrno = errno;

    if (text == NULL) {
      pr_trace_msg(trace_channel, 3, "error getting registry text: %s",
        strerror(xerrno));

      switch (xerrno) {
        case ENOENT:
          status_code = MHD_HTTP_NOT_FOUND;
          text = "Not Found\n";
          break;

        case EINVAL:
          status_code = MHD_HTTP_BAD_REQUEST;
          text = "Bad Request\n";
          break;

        default:
          status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
          text = "Internal Server Error\n";
          break;
      }

      textlen = strlen(text);

      resp = MHD_create_response_from_buffer(textlen, (void *) text,
        MHD_RESPMEM_PERSISTENT);
      (void) MHD_add_response_header(resp, MHD_HTTP_HEADER_CONTENT_TYPE,
        "text/plain");
      res = MHD_queue_response(conn, status_code, resp);
      MHD_destroy_response(resp);

      log_clf(resp_pool, conn, request_username, http_method, http_uri,
        http_version, status_code, textlen);
      destroy_pool(resp_pool);

      return res;
    }

    textlen = strlen(text);
    status_code = MHD_HTTP_OK;

    use_gzip = can_gzip(conn);
    if (use_gzip == TRUE) {
      const char *gzipped_text = NULL;
      size_t gzipped_textlen = 0;

      pr_trace_msg(trace_channel, 12,
        "client indicates support for gzip-compressed content, "
        "attempting to compress text (%lu bytes):\n%.*s",
        (unsigned long) textlen, (int) textlen, text);
      gzipped_text = gzip_text(resp_pool, text, textlen, &gzipped_textlen);
      if (gzipped_text != NULL) {
        text = gzipped_text;
        textlen = gzipped_textlen;
        pr_trace_msg(trace_channel, 19,
          "registry text:\n(gzip compressed, %lu bytes)", (size_t) textlen);

      } else {
        use_gzip = FALSE;
      }

    } else {
      pr_trace_msg(trace_channel, 19, "registry text:\n%.*s", (int) textlen,
        text);
    }

    resp = MHD_create_response_from_buffer(textlen, (void *) text,
      MHD_RESPMEM_MUST_COPY);
    (void) MHD_add_response_header(resp, MHD_HTTP_HEADER_CONTENT_TYPE,
      "text/plain");
    if (use_gzip == TRUE) {
      (void) MHD_add_response_header(resp, MHD_HTTP_HEADER_CONTENT_ENCODING,
        "gzip");
    }

    res = MHD_queue_response(conn, status_code, resp);
    MHD_destroy_response(resp);

    log_clf(resp_pool, conn, request_username, http_method, http_uri,
      http_version, status_code, textlen);
    destroy_pool(resp_pool);

    return res;
  }

  /* Note that we could use 404 Not Found here, but using 400 Bad Request
   * leaks less information.
   */
  status_code = MHD_HTTP_BAD_REQUEST;
  text = "Bad Request\n";
  textlen = strlen(text);

  resp = MHD_create_response_from_buffer(textlen, (void *) text,
    MHD_RESPMEM_PERSISTENT);
  (void) MHD_add_response_header(resp, MHD_HTTP_HEADER_CONTENT_TYPE,
    "text/plain");
  res = MHD_queue_response(conn, status_code, resp);
  MHD_destroy_response(resp);

  log_clf(resp_pool, conn, NULL, http_method, http_uri, http_version,
    status_code, textlen);
  destroy_pool(resp_pool);

  return res;
}

struct prom_http *prom_http_start(pool *p, const pr_netaddr_t *addr,
    struct prom_registry *registry, const char *username,
    const char *password) {
  struct prom_http *http;
  pool *http_pool;
  struct MHD_Daemon *mhd;
  unsigned int http_port;
  int flags;

  if (p == NULL ||
      addr == NULL ||
      registry == NULL) {
    errno = EINVAL;
    return NULL;
  }

  http_pool = make_sub_pool(p);
  pr_pool_tag(http_pool, "Prometheus exporter pool");

  http = pcalloc(http_pool, sizeof(struct prom_http));
  http->pool = http_pool;
  http->registry = registry;

  http_port = ntohs(pr_netaddr_get_port(addr));
  pr_trace_msg(trace_channel, 9, "starting exporter %son %s:%u",
    username != NULL ? "requiring basic auth " : "",
    pr_netaddr_get_ipstr(addr), http_port);

  flags = MHD_USE_INTERNAL_POLLING_THREAD|MHD_USE_ERROR_LOG|MHD_USE_DEBUG;
  mhd = MHD_start_daemon(flags, http_port, NULL, NULL,
    handle_request_cb, http,
    MHD_OPTION_EXTERNAL_LOGGER, log_cb, NULL,
    MHD_OPTION_CONNECTION_LIMIT, 1,
    MHD_OPTION_CONNECTION_TIMEOUT, 10,
    MHD_OPTION_SOCK_ADDR, pr_netaddr_get_sockaddr(addr),
    MHD_OPTION_END);
  if (mhd == NULL) {
    int xerrno = errno;

    /* Usually this happens because of an option specification issue. */
    (void) pr_log_writefile(prometheus_logfd, MOD_PROMETHEUS_VERSION,
      "error starting exporter: %s", strerror(xerrno));
    errno = xerrno;
    return NULL;
  }

  http->mhd = mhd;
  http_username = username;
  http_password = password;

  return http;
}

int prom_http_run_loop(pool *p, struct prom_http *http) {
  unsigned long sleep_ms = 500;

  if (p == NULL ||
      http == NULL) {
    errno = EINVAL;
    return -1;
  }

  (void) p;
  (void) http;

  /* Just run in a loop, handling signals. */
  while (TRUE) {
    pr_timer_usleep(sleep_ms * 1000);
    pr_signals_handle();
  }

  return 0;
}

int prom_http_stop(pool *p, struct prom_http *http) {
  if (p == NULL ||
      http == NULL) {
    errno = EINVAL;
    return -1;
  }

  (void) p;
  MHD_stop_daemon(http->mhd);

  return 0;
}

int prom_http_init(pool *p) {
  enum MHD_Result result;

  if (p == NULL) {
    errno = EINVAL;
    return -1;
  }

  MHD_set_panic_func(panic_cb, NULL);

  pr_trace_msg(trace_channel, 7, "libmicrohttpd version: %s",
    MHD_get_version());

  /* List of libmicrohttpd features in which we are interested. */
  result = MHD_is_feature_supported(MHD_FEATURE_MESSAGES);
  pr_trace_msg(trace_channel, 7, "  debug messages: %s",
    result == MHD_YES ? "true" : "false");

  result = MHD_is_feature_supported(MHD_FEATURE_TLS);
  pr_trace_msg(trace_channel, 7, "  TLS support: %s",
    result == MHD_YES ? "true" : "false");

  result = MHD_is_feature_supported(MHD_FEATURE_IPv6);
  pr_trace_msg(trace_channel, 7, "  IPv6 support: %s",
    result == MHD_YES ? "true" : "false");

  result = MHD_is_feature_supported(MHD_FEATURE_BASIC_AUTH);
  pr_trace_msg(trace_channel, 7, "  Basic Auth support: %s",
    result == MHD_YES ? "true" : "false");

  return 0;
}

int prom_http_free(void) {
  MHD_set_panic_func(NULL, NULL);
  return 0;
}
