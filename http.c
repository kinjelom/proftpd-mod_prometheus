/*
 * ProFTPD - mod_prometheus http implementation
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
#include "http.h"

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
#endif

struct prom_http {
  pool *pool;
  struct MHD_Daemon *mhd;
};

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

static enum MHD_Result handle_request_cb(void *user_data,
    struct MHD_Connection *conn, const char *http_uri, const char *http_method,
    const char *http_version, const char *request_body, size_t *request_bodysz,
    void **conn_user_data) {
  pool *http_pool, *resp_pool;
  unsigned int status_code;
  const char *text;
  size_t textlen;
  struct MHD_Response *resp = NULL;
  int res;

  http_pool = user_data;
  resp_pool = make_sub_pool(http_pool);
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
    status_code = MHD_HTTP_OK;
    text = pstrcat(resp_pool, "OK\n\n", NULL);
    textlen = strlen(text);

    resp = MHD_create_response_from_buffer(textlen, (void *) text,
      MHD_RESPMEM_MUST_COPY);
    (void) MHD_add_response_header(resp, MHD_HTTP_HEADER_CONTENT_TYPE,
      "text/plain");
    res = MHD_queue_response(conn, status_code, resp);
    MHD_destroy_response(resp);

    log_clf(resp_pool, conn, NULL, http_method, http_uri, http_version,
      status_code, textlen);
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

struct prom_http *prom_http_start(pool *p, unsigned short http_port) {
  struct prom_http *http;
  pool *http_pool;
  struct MHD_Daemon *mhd;
  int flags;

  if (p == NULL) {
    errno = EINVAL;
    return NULL;
  }

  http_pool = make_sub_pool(p);
  pr_pool_tag(http_pool, "Prometheus exporter pool");

  http = pcalloc(http_pool, sizeof(struct prom_http));
  http->pool = http_pool;

  pr_trace_msg(trace_channel, 9, "starting exporter on port %u", http_port);

  flags = MHD_USE_INTERNAL_POLLING_THREAD|MHD_USE_ERROR_LOG|MHD_USE_DEBUG;
  mhd = MHD_start_daemon(flags, http_port, NULL, NULL,
    handle_request_cb, http->pool,
    MHD_OPTION_EXTERNAL_LOGGER, log_cb, NULL,
    MHD_OPTION_CONNECTION_LIMIT, 1,
    MHD_OPTION_CONNECTION_TIMEOUT, 10,
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
