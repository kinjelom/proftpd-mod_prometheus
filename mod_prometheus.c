/*
 * ProFTPD - mod_prometheus
 * Copyright (c) 2021-2023 TJ Saunders
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
 *
 * -----DO NOT EDIT BELOW THIS LINE-----
 * $Archive: mod_prometheus.a $
 * $Libraries: -lmicrohttpd -lsqlite3$
 */

#include "mod_prometheus.h"
#include "prometheus/db.h"
#include "prometheus/registry.h"
#include "prometheus/metric.h"
#include "prometheus/metric/db.h"
#include "prometheus/http.h"

/* Defaults */
#define PROMETHEUS_DEFAULT_EXPORTER_PORT	9273

extern xaset_t *server_list;

int prometheus_logfd = -1;
module prometheus_module;
pool *prometheus_pool = NULL;

static int prometheus_engine = FALSE;
static unsigned long prometheus_opts = 0UL;
static const char *prometheus_tables_dir = NULL;
static uint64_t prometheus_connected_ms = 0;

static struct prom_dbh *prometheus_dbh = NULL;
static struct prom_registry *prometheus_registry = NULL;
static struct prom_http *prometheus_exporter_http = NULL;
static pid_t prometheus_exporter_pid = 0;

static int prometheus_saw_user_cmd = FALSE;
static int prometheus_saw_pass_cmd = FALSE;

/* Number of seconds to wait for the exporter process to stop before
 * we terminate it with extreme prejudice.
 *
 * Currently this has a granularity of seconds; needs to be in millsecs
 * (e.g. for 500 ms timeout).
 */
static time_t prometheus_exporter_timeout = 1;

/* mod_prometheus option flags */
#define PROM_OPT_ENABLE_LOG_MESSAGE_METRICS		0x001

static void prom_event_decr(const char *metric_name, uint32_t decr, ...)
#if defined(__GNUC__)
      __attribute__ ((sentinel));
#else
      ;
#endif /* GNUC */

static void prom_event_incr(const char *metric_name, uint32_t incr, ...)
#if defined(__GNUC__)
      __attribute__ ((sentinel));
#else
      ;
#endif /* GNUC */

static void prom_event_observe(const char *metric_name, double observed, ...)
#if defined(__GNUC__)
      __attribute__ ((sentinel));
#else
      ;
#endif /* GNUC */

static const char *trace_channel = "prometheus";

static int prom_mkdir(const char *dir, uid_t uid, gid_t gid, mode_t mode) {
  mode_t prev_mask;
  struct stat st;
  int res = -1;

  pr_fs_clear_cache2(dir);
  res = pr_fsio_stat(dir, &st);

  if (res == -1 &&
      errno != ENOENT) {
    return -1;
  }

  /* The directory already exists. */
  if (res == 0) {
    return 0;
  }

  /* The given mode is absolute, not subject to any Umask setting. */
  prev_mask = umask(0);

  if (pr_fsio_mkdir(dir, mode) < 0) {
    int xerrno = errno;

    (void) umask(prev_mask);
    errno = xerrno;
    return -1;
  }

  umask(prev_mask);

  if (pr_fsio_chown(dir, uid, gid) < 0) {
    return -1;
  }

  return 0;
}

static int prom_mkpath(pool *p, const char *path, uid_t uid, gid_t gid,
    mode_t mode) {
  char *currpath = NULL, *tmppath = NULL;
  struct stat st;

  pr_fs_clear_cache2(path);
  if (pr_fsio_stat(path, &st) == 0) {
    /* Path already exists, nothing to be done. */
    errno = EEXIST;
    return -1;
  }

  tmppath = pstrdup(p, path);

  currpath = "/";
  while (tmppath && *tmppath) {
    char *currdir = strsep(&tmppath, "/");
    currpath = pdircat(p, currpath, currdir, NULL);

    if (prom_mkdir(currpath, uid, gid, mode) < 0) {
      return -1;
    }

    pr_signals_handle();
  }

  return 0;
}

static int prom_openlog(void) {
  int res = 0;
  config_rec *c;

  c = find_config(main_server->conf, CONF_PARAM, "PrometheusLog", FALSE);
  if (c != NULL) {
    const char *path;

    path = c->argv[0];

    if (strncasecmp(path, "none", 5) != 0) {
      int xerrno;

      pr_signals_block();
      PRIVS_ROOT
      res = pr_log_openfile(path, &prometheus_logfd, 0600);
      xerrno = errno;
      PRIVS_RELINQUISH
      pr_signals_unblock();

      if (res < 0) {
        if (res == -1) {
          pr_log_pri(PR_LOG_NOTICE, MOD_PROMETHEUS_VERSION
            ": notice: unable to open PrometheusLog '%s': %s", path,
            strerror(xerrno));

        } else if (res == PR_LOG_WRITABLE_DIR) {
          pr_log_pri(PR_LOG_WARNING, MOD_PROMETHEUS_VERSION
            ": notice: unable to open PrometheusLog '%s': parent directory is "
            "world-writable", path);

        } else if (res == PR_LOG_SYMLINK) {
          pr_log_pri(PR_LOG_WARNING, MOD_PROMETHEUS_VERSION
            ": notice: unable to open PrometheusLog '%s': cannot log to "
            "a symlink", path);
        }
      }
    }
  }

  return res;
}

/* We don't want to do the full daemonize() as provided in main.c; we
 * already forked.
 */
static void prom_daemonize(const char *daemon_dir) {
#ifndef HAVE_SETSID
  int tty_fd;
#endif

#ifdef HAVE_SETSID
  /* setsid() is the preferred way to disassociate from the
   * controlling terminal
   */
  setsid();
#else
  /* Open /dev/tty to access our controlling tty (if any) */
  tty_fd = open("/dev/tty", O_RDWR);
  if (tty_fd != -1) {
    if (ioctl(tty_fd, TIOCNOTTY, NULL) == -1) {
      perror("ioctl");
      exit(1);
    }

    close(tty_fd);
  }
#endif /* HAVE_SETSID */

  /* Close the three big boys. */
  close(fileno(stdin));
  close(fileno(stdout));
  close(fileno(stderr));

  /* Portable way to prevent re-acquiring a tty in the future */

#if defined(HAVE_SETPGID)
  setpgid(0, getpid());

#else
# if defined(SETPGRP_VOID)
  setpgrp();

# else
  setpgrp(0, getpid());
# endif /* SETPGRP_VOID */
#endif /* HAVE_SETPGID */

  pr_fsio_chdir(daemon_dir, 0);
}

static pid_t prom_exporter_start(pool *p, const pr_netaddr_t *exporter_addr,
    const char *username, const char *password) {
  pid_t exporter_pid;
  struct prom_dbh *dbh;
  char *exporter_chroot = NULL;

  exporter_pid = fork();
  switch (exporter_pid) {
    case -1:
      pr_log_pri(PR_LOG_ALERT,
        MOD_PROMETHEUS_VERSION ": unable to fork: %s", strerror(errno));
      return 0;

    case 0:
      /* We're the child. */
      break;

    default:
      /* We're the parent. */
      return exporter_pid;
  }

  /* Reset the cached PID, so that it is correctly reflected in the logs. */
  session.pid = getpid();

  pr_trace_msg(trace_channel, 3, "forked exporter PID %lu",
    (unsigned long) session.pid);

  prom_daemonize(prometheus_tables_dir);

  /* Install our own signal handlers (mostly to ignore signals) */
  (void) signal(SIGALRM, SIG_IGN);
  (void) signal(SIGHUP, SIG_IGN);
  (void) signal(SIGUSR1, SIG_IGN);
  (void) signal(SIGUSR2, SIG_IGN);

  /* Remove our event listeners. */
  pr_event_unregister(&prometheus_module, NULL, NULL);

  /* Close any database handle inherited from our parent, and open a new
   * one, per SQLite3 recommendation.
   */
  (void) prom_db_close(prometheus_pool, prometheus_dbh);
  prometheus_dbh = NULL;
  dbh = prom_metric_db_open(prometheus_pool, prometheus_tables_dir);
  if (dbh == NULL) {
    pr_trace_msg(trace_channel, 3, "exporter error opening '%s' database: %s",
      prometheus_tables_dir, strerror(errno));
  }

  if (prom_registry_set_dbh(prometheus_registry, dbh) < 0) {
    pr_trace_msg(trace_channel, 3, "exporter error setting registry dbh: %s",
      strerror(errno));
  }

  PRIVS_ROOT
  if (getuid() == PR_ROOT_UID) {
    int res;

    /* Chroot to the PrometheusTables/empty/ directory before dropping
     * root privs.
     */
    exporter_chroot = pdircat(prometheus_pool, prometheus_tables_dir, "empty",
      NULL);
    res = chroot(exporter_chroot);
    if (res < 0) {
      int xerrno = errno;

      PRIVS_RELINQUISH
 
      (void) pr_log_writefile(prometheus_logfd, MOD_PROMETHEUS_VERSION,
        "unable to chroot to PrometheusTables/empty/ directory '%s': %s",
        exporter_chroot, strerror(xerrno));
      exit(0);
    }

    if (chdir("/") < 0) {
      int xerrno = errno;

      PRIVS_RELINQUISH

      (void) pr_log_writefile(prometheus_logfd, MOD_PROMETHEUS_VERSION,
        "unable to chdir to root directory within chroot: %s",
        strerror(xerrno));
      exit(0);
    }
  }

  pr_proctitle_set("(listening for Prometheus requests)");

  /* Make the exporter process have the identity of the configured daemon
   * User/Group.
   */
  session.uid = geteuid();
  session.gid = getegid();
  PRIVS_REVOKE

  prometheus_exporter_http = prom_http_start(p, exporter_addr,
    prometheus_registry, username, password);
  if (prometheus_exporter_http == NULL) {
    return 0;
  }

  if (exporter_chroot != NULL) {
    (void) pr_log_writefile(prometheus_logfd, MOD_PROMETHEUS_VERSION,
      "exporter process running with UID %s, GID %s, restricted to '%s'",
      pr_uid2str(prometheus_pool, getuid()),
      pr_gid2str(prometheus_pool, getgid()), exporter_chroot);

  } else {
    (void) pr_log_writefile(prometheus_logfd, MOD_PROMETHEUS_VERSION,
      "exporter process running with UID %s, GID %s, located in '%s'",
      pr_uid2str(prometheus_pool, getuid()),
      pr_gid2str(prometheus_pool, getgid()), getcwd(NULL, 0));
  }

  /* This function will exit once the exporter finishes. */
  prom_http_run_loop(p, prometheus_exporter_http);

  pr_trace_msg(trace_channel, 3, "exporter PID %lu exiting",
    (unsigned long) session.pid);
  exit(0);
}

static void prom_exporter_stop(pid_t exporter_pid) {
  int res, status;
  time_t start_time = time(NULL);

  if (exporter_pid == 0) {
    /* Nothing to do. */
    return;
  }

  pr_trace_msg(trace_channel, 3, "stopping exporter PID %lu",
    (unsigned long) exporter_pid);

  /* Litmus test: is the exporter process still around?  If not, there's
   * nothing for us to do.
   */
  res = kill(exporter_pid, 0);
  if (res < 0 &&
      errno == ESRCH) {
    return;
  }

  res = kill(exporter_pid, SIGTERM);
  if (res < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(prometheus_logfd, MOD_PROMETHEUS_VERSION,
      "error sending SIGTERM (signal %d) to exporter process ID %lu: %s",
      SIGTERM, (unsigned long) exporter_pid, strerror(xerrno));
  }

  /* Poll every 500 millsecs. */
  pr_timer_usleep(500 * 1000);

  res = waitpid(exporter_pid, &status, WNOHANG);
  while (res <= 0) {
    if (res < 0) {
      if (errno == EINTR) {
        pr_signals_handle();
        continue;
      }

      if (errno == ECHILD) {
        /* XXX Maybe we shouldn't be using waitpid(2) here, since the
         * main SIGCHLD handler may handle the termination of the exporter
         * process?
         */

        return;
      }

      if (errno != EINTR) {
        (void) pr_log_writefile(prometheus_logfd, MOD_PROMETHEUS_VERSION,
          "error waiting for exporter process ID %lu: %s",
          (unsigned long) exporter_pid, strerror(errno));
        status = -1;
        break;
      }
    }

    /* Check the time elapsed since we started. */
    if ((time(NULL) - start_time) > prometheus_exporter_timeout) {
      (void) pr_log_writefile(prometheus_logfd, MOD_PROMETHEUS_VERSION,
        "exporter process ID %lu took longer than timeout (%lu secs) to "
        "stop, sending SIGKILL (signal %d)", (unsigned long) exporter_pid,
        prometheus_exporter_timeout, SIGKILL);
      res = kill(exporter_pid, SIGKILL);
      if (res < 0) {
        (void) pr_log_writefile(prometheus_logfd, MOD_PROMETHEUS_VERSION,
         "error sending SIGKILL (signal %d) to exporter process ID %lu: %s",
         SIGKILL, (unsigned long) exporter_pid, strerror(errno));
      }

      break;
    }

    /* Poll every 500 millsecs. */
    pr_timer_usleep(500 * 1000);
  }

  if (WIFEXITED(status)) {
    int exit_status;

    exit_status = WEXITSTATUS(status);
    (void) pr_log_writefile(prometheus_logfd, MOD_PROMETHEUS_VERSION,
      "exporter process ID %lu terminated normally, with exit status %d",
      (unsigned long) exporter_pid, exit_status);
  }

  if (WIFSIGNALED(status)) {
    (void) pr_log_writefile(prometheus_logfd, MOD_PROMETHEUS_VERSION,
      "exporter process ID %lu died from signal %d",
      (unsigned long) exporter_pid, WTERMSIG(status));

    if (WCOREDUMP(status)) {
      (void) pr_log_writefile(prometheus_logfd, MOD_PROMETHEUS_VERSION,
        "exporter process ID %lu created a coredump",
        (unsigned long) exporter_pid);
    }
  }

  exporter_pid = 0;
  prometheus_exporter_http = NULL;
}

static pr_table_t *prom_get_labels(pool *p) {
  pr_table_t *labels;

  labels = pr_table_nalloc(p, 0, 2);
  (void) pr_table_add(labels, "protocol", pr_session_get_protocol(0), 0);

  return labels;
}

static const struct prom_metric *prom_metric_with_labels(pool *p,
    const char *metric_name, pr_table_t *labels, va_list ap) {
  char *key;
  const struct prom_metric *metric;

  metric = prom_registry_get_metric(prometheus_registry, metric_name);
  if (metric == NULL) {
    pr_trace_msg(trace_channel, 17, "unknown metric name '%s' requested",
      metric_name);
    return NULL;
  }

  key = va_arg(ap, char *);
  while (key != NULL) {
    char *val;

    pr_signals_handle();

    val = va_arg(ap, char *);

    /* Any labels provided by the caller take precedence. */
    if (pr_table_exists(labels, key) > 0) {
      (void) pr_table_set(labels, key, pstrdup(p, val), 0);

    } else {
      (void) pr_table_add_dup(labels, key, val, 0);
    }

    key = va_arg(ap, char *);
  }
  va_end(ap);

  return metric;
}

static void prom_event_decr(const char *metric_name, uint32_t decr, ...) {
  int res;
  pool *tmp_pool;
  va_list ap;
  const struct prom_metric *metric;
  pr_table_t *labels;

  if (session.pool != NULL) {
    tmp_pool = make_sub_pool(session.pool);

  } else {
    tmp_pool = make_sub_pool(prometheus_pool);
  }

  labels = prom_get_labels(tmp_pool);

  va_start(ap, decr);
  metric = prom_metric_with_labels(tmp_pool, metric_name, labels, ap);
  va_end(ap);

  if (metric == NULL) {
    destroy_pool(tmp_pool);
    return;
  }

  res = prom_metric_decr(tmp_pool, metric, decr, labels);
  if (res < 0) {
    pr_trace_msg(trace_channel, 19, "error decrementing %s: %s", metric_name,
      strerror(errno));
  }

  destroy_pool(tmp_pool);
}

static void prom_event_incr(const char *metric_name, uint32_t incr, ...) {
  int res;
  pool *tmp_pool;
  va_list ap;
  const struct prom_metric *metric;
  pr_table_t *labels;

  if (session.pool != NULL) {
    tmp_pool = make_sub_pool(session.pool);

  } else {
    tmp_pool = make_sub_pool(prometheus_pool);
  }

  labels = prom_get_labels(tmp_pool);

  va_start(ap, incr);
  metric = prom_metric_with_labels(tmp_pool, metric_name, labels, ap);
  va_end(ap);

  if (metric == NULL) {
    destroy_pool(tmp_pool);
    return;
  }

  res = prom_metric_incr(tmp_pool, metric, incr, labels);
  if (res < 0) {
    pr_trace_msg(trace_channel, 19, "error incrementing %s: %s", metric_name,
      strerror(errno));
  }

  destroy_pool(tmp_pool);
}

static void prom_event_observe(const char *metric_name, double observed, ...) {
  int res;
  pool *tmp_pool;
  va_list ap;
  const struct prom_metric *metric;
  pr_table_t *labels;

  if (session.pool != NULL) {
    tmp_pool = make_sub_pool(session.pool);

  } else {
    tmp_pool = make_sub_pool(prometheus_pool);
  }

  labels = prom_get_labels(tmp_pool);

  va_start(ap, observed);
  metric = prom_metric_with_labels(tmp_pool, metric_name, labels, ap);
  va_end(ap);

  if (metric == NULL) {
    destroy_pool(tmp_pool);
    return;
  }

  res = prom_metric_observe(tmp_pool, metric, observed, labels);
  if (res < 0) {
    pr_trace_msg(trace_channel, 19, "error observing %s: %s", metric_name,
      strerror(errno));
  }

  destroy_pool(tmp_pool);
}

/* Configuration handlers
 */

/* usage: PrometheusEngine on|off */
MODRET set_prometheusengine(cmd_rec *cmd) {
  int engine = -1;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  engine = get_boolean(cmd, 1);
  if (engine == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = engine;

  return PR_HANDLED(cmd);
}

/* usage: PrometheusExporter address[:port] [username password] */
MODRET set_prometheusexporter(cmd_rec *cmd) {
  char *addr, *ptr;
  size_t addrlen;
  config_rec *c;
  pr_netaddr_t *exporter_addr;
  int exporter_port = PROMETHEUS_DEFAULT_EXPORTER_PORT;

  if (cmd->argc < 2 ||
      cmd->argc > 4) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT);

  c = add_config_param(cmd->argv[0], 3, NULL, NULL, NULL);

  /* Separate the port out from the address, if present. */
  ptr = strrchr(cmd->argv[1], ':');
  if (ptr != NULL) {
    char *ptr2;

    /* We need to handle the following possibilities:
     *
     *  ipv4-addr
     *  ipv4-addr:port
     *  [ipv6-addr]
     *  [ipv6-addr]:port
     *
     * Thus we check to see if the last ':' occurs before, or after,
     * a ']' for an IPv6 address.
     */

    ptr2 = strrchr(cmd->argv[1], ']');
    if (ptr2 != NULL) {
      if (ptr2 > ptr) {
        /* The found ':' is part of an IPv6 address, not a port delimiter. */
        ptr = NULL;
      }
    }

    if (ptr != NULL) {
      *ptr = '\0';

      exporter_port = atoi(ptr + 1);
      if (exporter_port < 1 ||
          exporter_port > 65535) {
        CONF_ERROR(cmd, "port must be between 1-65535");
      }
    }
  }

  addr = cmd->argv[1];
  addrlen = strlen(addr);

  /* Make sure we can handle an IPv6 address here, e.g.:
   *
   *   [::1]:162
   */
  if (addrlen > 0 &&
      (addr[0] == '[' && addr[addrlen-1] == ']')) {
    addr = pstrndup(cmd->pool, addr + 1, addrlen - 2);
  }

  /* Watch for wildcard addresses. */
  if (strcmp(addr, "0.0.0.0") == 0) {
    exporter_addr = pr_netaddr_alloc(c->pool);
    pr_netaddr_set_family(exporter_addr, AF_INET);
    pr_netaddr_set_sockaddr_any(exporter_addr);

#if defined(PR_USE_IPV6)
  } else if (strcmp(addr, "::") == 0) {
    exporter_addr = pr_netaddr_alloc(c->pool);
    pr_netaddr_set_family(exporter_addr, AF_INET6);
    pr_netaddr_set_sockaddr_any(exporter_addr);
#endif /* PR_USE_IPV6 */

  } else {
    exporter_addr = (pr_netaddr_t *) pr_netaddr_get_addr(c->pool, addr, NULL);
    if (exporter_addr == NULL) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
        "unable to resolve \"", addr, "\"", NULL));
    }
  }

  pr_netaddr_set_port2(exporter_addr, exporter_port);
  c->argv[0] = exporter_addr;

  if (cmd->argc > 2) {
    if (cmd->argc == 3) {
      /* Only username provided?  Why? */
      CONF_ERROR(cmd, "wrong number of parameters");
    }

    c->argv[1] = pstrdup(c->pool, cmd->argv[2]);
    c->argv[2] = pstrdup(c->pool, cmd->argv[3]);
  }
 
  return PR_HANDLED(cmd);
}

/* usage: PrometheusLog path|"none" */
MODRET set_prometheuslog(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  (void) add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: PrometheusOptions opt1 ... optN */
MODRET set_prometheusoptions(cmd_rec *cmd) {
  config_rec *c = NULL;
  register unsigned int i;
  unsigned long opts = 0UL;

  if (cmd->argc-1 == 0) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT);

  c = add_config_param(cmd->argv[0], 1, NULL);

  for (i = 1; i < cmd->argc; i++) {
    if (strcasecmp(cmd->argv[i], "EnableLogMessageMetrics") == 0) {
      opts |= PROM_OPT_ENABLE_LOG_MESSAGE_METRICS;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown PrometheusOption '",
        cmd->argv[i], "'", NULL));
    }
  }

  c->argv[0] = pcalloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[0]) = opts;
 
  return PR_HANDLED(cmd);
}

/* usage: PrometheusTables path */
MODRET set_prometheustables(cmd_rec *cmd) {
  int res;
  struct stat st;
  char *path;
 
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  path = cmd->argv[1]; 
  if (*path != '/') {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "must be a full path: '", path, "'",
      NULL));
  }

  res = stat(path, &st);
  if (res < 0) {
    char *exporter_chroot;

    if (errno != ENOENT) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to stat '", path, "': ",
        strerror(errno), NULL));
    }

    pr_log_debug(DEBUG0, MOD_PROMETHEUS_VERSION
      ": PrometheusTables directory '%s' does not exist, creating it", path);

    /* Create the directory. */
    res = prom_mkpath(cmd->tmp_pool, path, geteuid(), getegid(), 0755);
    if (res < 0) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to create directory '",
        path, "': ", strerror(errno), NULL));
    }

    /* Also create the empty/ directory underneath, for the chroot. */
    exporter_chroot = pdircat(cmd->tmp_pool, path, "empty", NULL);

    res = prom_mkpath(cmd->tmp_pool, exporter_chroot, geteuid(), getegid(),
      0111);
    if (res < 0) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to create directory '",
        exporter_chroot, "': ", strerror(errno), NULL));
    }

    pr_log_debug(DEBUG2, MOD_PROMETHEUS_VERSION
      ": created PrometheusTables directory '%s'", path);

  } else {
    char *exporter_chroot;

    if (!S_ISDIR(st.st_mode)) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to use '", path,
        ": Not a directory", NULL));
    }

    /* See if the chroot directory empty/ already exists as well.  And enforce
     * the permissions on that directory.
     */
    exporter_chroot = pdircat(cmd->tmp_pool, path, "empty", NULL);

    res = stat(exporter_chroot, &st);
    if (res < 0) {
      if (errno != ENOENT) {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to stat '",
          exporter_chroot, "': ", strerror(errno), NULL));
      }

      res = prom_mkpath(cmd->tmp_pool, exporter_chroot, geteuid(), getegid(),
        0111);
      if (res < 0) {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to create directory '",
          exporter_chroot, "': ", strerror(errno), NULL));
      }

    } else {
      mode_t dir_mode, expected_mode;

      dir_mode = st.st_mode;
      dir_mode &= ~S_IFMT;
      expected_mode = (S_IXUSR|S_IXGRP|S_IXOTH);

      if (dir_mode != expected_mode) {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "directory '", exporter_chroot,
          "' has incorrect permissions (not 0111 as required)", NULL));
      }
    }
  }

  (void) add_config_param_str(cmd->argv[0], 1, path);
  return PR_HANDLED(cmd);
}

/* Command handlers
 */

static void prom_cmd_decr(cmd_rec *cmd, const char *metric_name,
    pr_table_t *labels) {
  const struct prom_metric *metric;

  metric = prom_registry_get_metric(prometheus_registry, metric_name);
  if (metric != NULL) {
    if (labels == NULL) {
      labels = prom_get_labels(cmd->tmp_pool);
    }

    prom_metric_decr(cmd->tmp_pool, metric, 1, labels);

  } else {
    pr_trace_msg(trace_channel, 19, "%s: unknown '%s' metric requested",
      (char *) cmd->argv[0], metric_name);
  }
}

static void prom_cmd_incr_type(cmd_rec *cmd, const char *metric_name,
    pr_table_t *labels, int metric_type) {
  const struct prom_metric *metric;

  metric = prom_registry_get_metric(prometheus_registry, metric_name);
  if (metric != NULL) {
    if (labels == NULL) {
      labels = prom_get_labels(cmd->tmp_pool);
    }

    prom_metric_incr_type(cmd->tmp_pool, metric, 1, labels, metric_type);

  } else {
    pr_trace_msg(trace_channel, 19, "%s: unknown '%s' metric requested",
      (char *) cmd->argv[0], metric_name);
  }
}

static void prom_cmd_observe(cmd_rec *cmd, const char *metric_name, double val,
    pr_table_t *labels) {
  const struct prom_metric *metric;

  metric = prom_registry_get_metric(prometheus_registry, metric_name);
  if (metric != NULL) {
    if (labels == NULL) {
      labels = prom_get_labels(cmd->tmp_pool);
    }

    prom_metric_observe(cmd->tmp_pool, metric, val, labels);

  } else {
    pr_trace_msg(trace_channel, 19, "%s: unknown '%s' metric requested",
      (char *) cmd->argv[0], metric_name);
  }
}

MODRET prom_pre_list(cmd_rec *cmd) {
  if (prometheus_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  prom_cmd_incr_type(cmd, "directory_list", NULL, PROM_METRIC_TYPE_GAUGE);
  return PR_DECLINED(cmd);
}

MODRET prom_log_list(cmd_rec *cmd) {
  const char *metric_name;

  if (prometheus_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  metric_name = "directory_list";
  prom_cmd_incr_type(cmd, metric_name, NULL, PROM_METRIC_TYPE_COUNTER);
  prom_cmd_decr(cmd, metric_name, NULL);
  return PR_DECLINED(cmd);
}

MODRET prom_err_list(cmd_rec *cmd) {
  if (prometheus_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  prom_cmd_incr_type(cmd, "directory_list_error", NULL,
    PROM_METRIC_TYPE_COUNTER);
  prom_cmd_decr(cmd, "directory_list", NULL);
  return PR_DECLINED(cmd);
}

MODRET prom_pre_user(cmd_rec *cmd) {
  if (prometheus_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  /* Logins begin at the first USER command seen; subsequent USER commands
   * are ignored, for purposes of the gauge.
   *
   * Logins end either at successful login, or end of connection.
   */
  if (prometheus_saw_user_cmd == FALSE) {
    prom_cmd_incr_type(cmd, "login", NULL, PROM_METRIC_TYPE_GAUGE);
    prometheus_saw_user_cmd = TRUE;
    prometheus_saw_pass_cmd = FALSE;
  }

  return PR_DECLINED(cmd);
}

MODRET prom_pre_pass(cmd_rec *cmd) {
  if (prometheus_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  if (prometheus_saw_user_cmd == FALSE) {
    return PR_DECLINED(cmd);
  }

  /* Used for tracking "incomplete" logins. */
  prometheus_saw_pass_cmd = TRUE;

  return PR_DECLINED(cmd);
}

MODRET prom_log_pass(cmd_rec *cmd) {
  const char *metric_name;
  pr_table_t *labels;
  uint64_t now_ms = 0;

  if (prometheus_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  if (prometheus_saw_user_cmd == FALSE) {
    return PR_DECLINED(cmd);
  }

  /* Easiest way for us to check for anonymous logins is here; the <Anonymous>
   * auth flow does not use the "mod_auth.authentication-code" event.
   */
  if (session.sf_flags & SF_ANON) {
    prom_event_incr("auth", 1, "method", "anonymous", NULL);
  }

  metric_name = "login";
  labels = prom_get_labels(cmd->tmp_pool);

  prom_cmd_incr_type(cmd, metric_name, labels, PROM_METRIC_TYPE_COUNTER);
  prom_cmd_decr(cmd, metric_name, labels);

  pr_gettimeofday_millis(&now_ms);
  prom_cmd_observe(cmd, metric_name,
    (double) ((now_ms - prometheus_connected_ms) / 1000), labels);
  return PR_DECLINED(cmd);
}

MODRET prom_err_login(cmd_rec *cmd) {
  if (prometheus_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  prom_cmd_incr_type(cmd, "login_error", NULL, PROM_METRIC_TYPE_COUNTER);

  /* Note that we never decrement the "login" gauge here.  Why not?  A
   * failed USER or PASS command could happen for multiple reasons (bad
   * sequence, wrong password that will be followed by a correct one, etc).
   * Thus the "login" gauge should only be decremented by a successful login,
   * or end of connection.
   */

  return PR_DECLINED(cmd);
}

MODRET prom_pre_retr(cmd_rec *cmd) {
  if (prometheus_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  prom_cmd_incr_type(cmd, "file_download", NULL, PROM_METRIC_TYPE_GAUGE);
  return PR_DECLINED(cmd);
}

MODRET prom_log_retr(cmd_rec *cmd) {
  const char *metric_name;
  pr_table_t *labels;

  if (prometheus_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  metric_name = "file_download";
  labels = prom_get_labels(cmd->tmp_pool);
  prom_cmd_incr_type(cmd, metric_name, labels, PROM_METRIC_TYPE_COUNTER);
  prom_cmd_decr(cmd, metric_name, labels);
  prom_cmd_observe(cmd, metric_name, session.xfer.total_bytes, labels);
  return PR_DECLINED(cmd);
}

MODRET prom_err_retr(cmd_rec *cmd) {
  if (prometheus_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  prom_cmd_incr_type(cmd, "file_download_error", NULL,
    PROM_METRIC_TYPE_COUNTER);
  prom_cmd_decr(cmd, "file_download", NULL);
  return PR_DECLINED(cmd);
}

MODRET prom_pre_stor(cmd_rec *cmd) {
  if (prometheus_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  prom_cmd_incr_type(cmd, "file_upload", NULL, PROM_METRIC_TYPE_GAUGE);
  return PR_DECLINED(cmd);
}

MODRET prom_log_stor(cmd_rec *cmd) {
  const char *metric_name;
  pr_table_t *labels;

  if (prometheus_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  metric_name = "file_upload";
  labels = prom_get_labels(cmd->tmp_pool);
  prom_cmd_incr_type(cmd, metric_name, labels, PROM_METRIC_TYPE_COUNTER);
  prom_cmd_decr(cmd, metric_name, labels);
  prom_cmd_observe(cmd, metric_name, session.xfer.total_bytes, labels);
  return PR_DECLINED(cmd);
}

MODRET prom_err_stor(cmd_rec *cmd) {
  if (prometheus_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  prom_cmd_incr_type(cmd, "file_upload_error", NULL,
    PROM_METRIC_TYPE_COUNTER);
  prom_cmd_decr(cmd, "file_upload", NULL);
  return PR_DECLINED(cmd);
}

MODRET prom_log_auth(cmd_rec *cmd) {
  const char *metric_name;
  const struct prom_metric *metric;

  if (prometheus_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  /* Note: we are not currently properly incrementing
   * session{protocol="ftps"} for FTPS connections accepted using the
   * UseImplicitSSL TLSOption.
   *
   * The issue is that for those connections, the protocol will be set to
   * "ftps" in mod_tls' sess_init callback.  But here in mod_prometheus, we
   * are not guaranteed to being called AFTER mod_tls, due to module load
   * ordering.  Thus we do not have a good way of determining when to
   * increment those counts for implicit FTPS connections.
   */

  metric_name = "tls_protocol";
  metric = prom_registry_get_metric(prometheus_registry, metric_name);
  if (metric != NULL) {
    pr_table_t *labels;
    const char *tls_version;

    labels = prom_get_labels(cmd->tmp_pool);

    tls_version = pr_table_get(session.notes, "TLS_PROTOCOL", NULL);
    if (tls_version == NULL) {
      /* Try the environment. */
      tls_version = pr_env_get(cmd->tmp_pool, "TLS_PROTOCOL");
    }

    if (tls_version != NULL) {
      (void) pr_table_add_dup(labels, "version", tls_version, 0);
    }

    prom_metric_incr(cmd->tmp_pool, metric, 1, labels);

  } else {
    pr_trace_msg(trace_channel, 19, "%s: unknown '%s' metric requested",
      (char *) cmd->argv[0], metric_name);
  }

  return PR_DECLINED(cmd);
}

/* Event listeners
 */

static void prom_auth_code_ev(const void *event_data, void *user_data) {
  int auth_code;

  if (prometheus_engine == FALSE) {
    return;
  }

  auth_code = *((int *) event_data);

  switch (auth_code) {
    case PR_AUTH_OK_NO_PASS:
      prom_event_incr("auth", 1, "method", session.rfc2228_mech, NULL);
      break;

    case PR_AUTH_RFC2228_OK:
      prom_event_incr("auth", 1, "method", "certificate", NULL);
      break;

    case PR_AUTH_OK:
      prom_event_incr("auth", 1, "method", "password", NULL);
      break;

    case PR_AUTH_NOPWD:
      prom_event_incr("auth_error", 1, "reason", "unknown user", NULL);
      break;

    case PR_AUTH_BADPWD:
      prom_event_incr("auth_error", 1, "reason", "bad password", NULL);
      break;

    default:
      prom_event_incr("auth_error", 1, NULL);
      break;
  }
}

static void prom_connect_ev(const void *event_data, void *user_data) {
  int flags;
  struct prom_dbh *dbh;

  /* Close any database handle inherited from our parent, and open a new
   * one, per SQLite3 recommendation.
   *
   * NOTE: session.pool does NOT exist yet.
   */
  (void) prom_db_close(prometheus_pool, prometheus_dbh);
  prometheus_dbh = NULL;

  flags = PROM_DB_OPEN_FL_VACUUM|PROM_DB_OPEN_FL_SKIP_TABLE_INIT;
  dbh = prom_metric_db_init(prometheus_pool, prometheus_tables_dir, flags);
  if (dbh == NULL) {
    pr_trace_msg(trace_channel, 1,
      "error initializing '%s' metrics db at connect time: %s",
      prometheus_tables_dir, strerror(errno));

  } else {
    if (prom_registry_set_dbh(prometheus_registry, dbh) < 0) {
      pr_trace_msg(trace_channel, 3, "error setting registry dbh: %s",
        strerror(errno));
    }
  }
}

static void prom_exit_ev(const void *event_data, void *user_data) {
  if (prometheus_engine == FALSE) {
    return;
  }

  switch (session.disconnect_reason) {
    case PR_SESS_DISCONNECT_BANNED:
    case PR_SESS_DISCONNECT_CONFIG_ACL:
    case PR_SESS_DISCONNECT_MODULE_ACL:
    case PR_SESS_DISCONNECT_SESSION_INIT_FAILED: {
      const void *reason;

      reason = pr_table_get(session.notes, "core.disconnect-details", NULL);
      if (reason != NULL) {
        prom_event_incr("connection_refused", 1, "reason", reason, NULL);

      } else {
        prom_event_incr("connection_refused", 1, NULL);
      }
      break;
    }

    case PR_SESS_DISCONNECT_SEGFAULT:
      prom_event_decr("connection", 1, NULL);
      prom_event_incr("segfault", 1, NULL);
      break;

    default: {
      uint64_t now_ms = 0;

      if (prometheus_saw_user_cmd == TRUE &&
          session.user == NULL) {
        /* Login was started, but not completed. */
        prom_event_decr("login", 1, NULL);

        if (prometheus_saw_pass_cmd == FALSE) {
          prom_event_incr("auth_error", 1, "reason", "incomplete", NULL);
        }
      }

      prom_event_decr("connection", 1, NULL);

      pr_gettimeofday_millis(&now_ms);
      prom_event_observe("connection",
        (double) ((now_ms - prometheus_connected_ms) / 1000), NULL);
      break;
    }
  }

  prom_http_free();

  if (prometheus_logfd >= 0) {
    (void) close(prometheus_logfd);
    prometheus_logfd = -1;
  }
}

static void prom_log_msg_ev(const void *event_data, void *user_data) {
  pool *tmp_pool;
  int res;
  const char *metric_name, *level_text = NULL;
  const struct prom_metric *metric;
  const pr_log_event_t *le;
  pr_table_t *labels;

  metric_name = "log_message";
  metric = prom_registry_get_metric(prometheus_registry, metric_name);
  if (metric == NULL) {
    pr_trace_msg(trace_channel, 17, "unknown metric name '%s' requested",
      metric_name);
    return;
  }

  le = event_data;
  switch (le->log_level) {
    case PR_LOG_EMERG:
      level_text = "emerg";
      break;

    case PR_LOG_ALERT:
      level_text = "alert";
      break;

    case PR_LOG_CRIT:
      level_text = "crit";
      break;

    case PR_LOG_ERR:
      level_text = "error";
      break;

    case PR_LOG_WARNING:
      level_text = "warn";
      break;

    case PR_LOG_NOTICE:
      level_text = "notice";
      break;

    case PR_LOG_INFO:
      level_text = "info";
      break;

    case PR_LOG_DEBUG:
      level_text = "debug";
      break;

    default:
      level_text = NULL;
      break;
  }

  if (level_text == NULL) {
    return;
  }

  if (session.pool != NULL) {
    tmp_pool = make_sub_pool(session.pool);

  } else {
    tmp_pool = make_sub_pool(prometheus_pool);
  }

  labels = prom_get_labels(tmp_pool);
  (void) pr_table_add_dup(labels, "level", level_text, 0);
  res = prom_metric_incr(tmp_pool, metric, 1, labels);
  if (res < 0) {
    pr_trace_msg(trace_channel, 19, "error increment %s: %s", metric_name,
      strerror(errno));
  }

  destroy_pool(tmp_pool);
}

#if defined(PR_SHARED_MODULE)
static void prom_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp((const char *) event_data, "mod_prometheus.c") != 0) {
    return;
  }

  /* Unregister ourselves from all events. */
  pr_event_unregister(&prometheus_module, NULL, NULL);

  (void) prom_db_close(prometheus_pool, prometheus_dbh);
  prometheus_dbh = NULL;
  prometheus_exporter_http = NULL;

  (void) prom_registry_free(prometheus_registry);
  prometheus_registry = NULL;
  prometheus_tables_dir = NULL;

  destroy_pool(prometheus_pool);
  prometheus_pool = NULL;

  (void) close(prometheus_logfd);
  prometheus_logfd = -1;
}
#endif /* PR_SHARED_MODULE */

static void create_session_metrics(pool *p, struct prom_dbh *dbh) {
  int res;
  struct prom_metric *metric;

  /* Session metrics:
   *
   *  auth
   *  auth_error
   *  connection
   *  directory_list
   *  directory_list_error
   *  file_download
   *  file_download_error
   *  file_upload
   *  file_upload_error
   *  login
   *  login_error
   *  timeout
   *  handshake_error
   *  tls_protocol
   *  sftp_protocol
   */

  metric = prom_metric_create(prometheus_pool, "auth", dbh);
  prom_metric_add_counter(metric, "total",
    "Number of successful authentications");
  res = prom_registry_add_metric(prometheus_registry, metric);
  if (res < 0) {
    pr_trace_msg(trace_channel, 1, "error registering metric '%s': %s",
      prom_metric_get_name(metric), strerror(errno));
  }

  metric = prom_metric_create(prometheus_pool, "auth_error", dbh);
  prom_metric_add_counter(metric, "total",
    "Number of failed authentications");
  res = prom_registry_add_metric(prometheus_registry, metric);
  if (res < 0) {
    pr_trace_msg(trace_channel, 1, "error registering metric '%s': %s",
      prom_metric_get_name(metric), strerror(errno));
  }

  metric = prom_metric_create(prometheus_pool, "connection", dbh);
  prom_metric_add_counter(metric, "total", "Number of connections");
  prom_metric_add_gauge(metric, "count", "Current count of connections");

  /* Create histogram buckets for connection duration of:
   *   1s, 5s, 10s, 30s, 1m, 5m, 10m, 1h, 6h, 1d
   */
  prom_metric_add_histogram(metric, "duration_seconds",
    "Connection durations in seconds", 11, (double) 1, (double) 5, (double) 10,
    (double) 30, (double) 60, (double) 300, (double) 600, (double) 1800,
    (double) 3600, (double) 21600, (double) 86400);
  res = prom_registry_add_metric(prometheus_registry, metric);
  if (res < 0) {
    pr_trace_msg(trace_channel, 1, "error registering metric '%s': %s",
      prom_metric_get_name(metric), strerror(errno));
  }

  metric = prom_metric_create(prometheus_pool, "directory_list", dbh);
  prom_metric_add_counter(metric, "total",
    "Number of succesful directory listings");
  prom_metric_add_gauge(metric, "count", "Current count of directory listings");
  res = prom_registry_add_metric(prometheus_registry, metric);
  if (res < 0) {
    pr_trace_msg(trace_channel, 1, "error registering metric '%s': %s",
      prom_metric_get_name(metric), strerror(errno));
  }

  metric = prom_metric_create(prometheus_pool, "directory_list_error", dbh);
  prom_metric_add_counter(metric, "total",
    "Number of failed directory listings");
  res = prom_registry_add_metric(prometheus_registry, metric);
  if (res < 0) {
    pr_trace_msg(trace_channel, 1, "error registering metric '%s': %s",
      prom_metric_get_name(metric), strerror(errno));
  }

  metric = prom_metric_create(prometheus_pool, "file_download", dbh);
  prom_metric_add_counter(metric, "total",
    "Number of successful file downloads");
  prom_metric_add_gauge(metric, "count", "Current count of file downloads");

  /* Create histogram buckets for file download bytes of:
   *   10K, 50K, 100K, 1M, 10M, 50M, 100M, 500M, 1G, 100G
   */
  prom_metric_add_histogram(metric, "bytes",
    "Amount of data downloaded in bytes", 10, (double) 10240, (double) 51200,
    (double) 102400, (double) 1048576, (double) 10485760, (double) 52428800,
    (double) 104857600, (double) 524288000, (double) 1073741824,
    (double) 107374182400);
  res = prom_registry_add_metric(prometheus_registry, metric);
  if (res < 0) {
    pr_trace_msg(trace_channel, 1, "error registering metric '%s': %s",
      prom_metric_get_name(metric), strerror(errno));
  }

  metric = prom_metric_create(prometheus_pool, "file_download_error", dbh);
  prom_metric_add_counter(metric, "total", "Number of failed file downloads");
  res = prom_registry_add_metric(prometheus_registry, metric);
  if (res < 0) {
    pr_trace_msg(trace_channel, 1, "error registering metric '%s': %s",
      prom_metric_get_name(metric), strerror(errno));
  }

  metric = prom_metric_create(prometheus_pool, "file_upload", dbh);
  prom_metric_add_counter(metric, "total", "Number of successful file uploads");
  prom_metric_add_gauge(metric, "count", "Current count of file uploads");

  /* Create histogram buckets for file upload bytes of:
   *   10K, 50K, 100K, 1M, 10M, 50M, 100M, 500M, 1G, 100G
   */
  prom_metric_add_histogram(metric, "bytes",
    "Amount of data uploaded in bytes", 10, (double) 10240, (double) 51200,
    (double) 102400, (double) 1048576, (double) 10485760, (double) 52428800,
    (double) 104857600, (double) 524288000, (double) 1073741824,
    (double) 107374182400);
  res = prom_registry_add_metric(prometheus_registry, metric);
  if (res < 0) {
    pr_trace_msg(trace_channel, 1, "error registering metric '%s': %s",
      prom_metric_get_name(metric), strerror(errno));
  }

  metric = prom_metric_create(prometheus_pool, "file_upload_error", dbh);
  prom_metric_add_counter(metric, "total", "Number of failed file uploads");
  res = prom_registry_add_metric(prometheus_registry, metric);
  if (res < 0) {
    pr_trace_msg(trace_channel, 1, "error registering metric '%s': %s",
      prom_metric_get_name(metric), strerror(errno));
  }

  metric = prom_metric_create(prometheus_pool, "login", dbh);
  prom_metric_add_counter(metric, "total", "Number of successful logins");
  prom_metric_add_gauge(metric, "count", "Current count of logins");

  /* Create histogram buckets for login duration of:
   *   10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1s, 2.5s, 5s, 10s, 30s
   */
  prom_metric_add_histogram(metric, "delay_seconds",
    "Delay before login in seconds", 11, (double) 0.01, (double) 0.025,
    (double) 0.05, (double) 0.1, (double) 0.25, (double) 0.5, (double) 1.0,
    (double) 2.5, (double) 5.0, (double) 10.0, (double) 30.0);
  res = prom_registry_add_metric(prometheus_registry, metric);
  if (res < 0) {
    pr_trace_msg(trace_channel, 1, "error registering metric '%s': %s",
      prom_metric_get_name(metric), strerror(errno));
  }

  metric = prom_metric_create(prometheus_pool, "login_error", dbh);
  prom_metric_add_counter(metric, "total", "Number of failed logins");
  res = prom_registry_add_metric(prometheus_registry, metric);
  if (res < 0) {
    pr_trace_msg(trace_channel, 1, "error registering metric '%s': %s",
      prom_metric_get_name(metric), strerror(errno));
  }

  metric = prom_metric_create(prometheus_pool, "timeout", dbh);
  prom_metric_add_counter(metric, "total", "Number of timeouts");
  res = prom_registry_add_metric(prometheus_registry, metric);
  if (res < 0) {
    pr_trace_msg(trace_channel, 1, "error registering metric '%s': %s",
      prom_metric_get_name(metric), strerror(errno));
  }

  metric = prom_metric_create(prometheus_pool, "handshake_error", dbh);
  prom_metric_add_counter(metric, "total",
    "Number of failed SFTP/TLS handshakes");
  res = prom_registry_add_metric(prometheus_registry, metric);
  if (res < 0) {
    pr_trace_msg(trace_channel, 1, "error registering metric '%s': %s",
      prom_metric_get_name(metric), strerror(errno));
  }

  metric = prom_metric_create(prometheus_pool, "sftp_protocol", dbh);
  prom_metric_add_counter(metric, "total",
    "Number of SFTP sessions by protocol version");
  res = prom_registry_add_metric(prometheus_registry, metric);
  if (res < 0) {
    pr_trace_msg(trace_channel, 1, "error registering metric '%s': %s",
      prom_metric_get_name(metric), strerror(errno));
  }

  metric = prom_metric_create(prometheus_pool, "tls_protocol", dbh);
  prom_metric_add_counter(metric, "total",
    "Number of TLS sessions by protocol version");
  res = prom_registry_add_metric(prometheus_registry, metric);
  if (res < 0) {
    pr_trace_msg(trace_channel, 1, "error registering metric '%s': %s",
      prom_metric_get_name(metric), strerror(errno));
  }
}

static void create_server_metrics(pool *p, struct prom_dbh *dbh) {
  int res;
  struct prom_metric *metric;

  /* Server metrics:
   *
   *  connection_refused
   *  log_message
   *  segfault
   */

  metric = prom_metric_create(prometheus_pool, "connection_refused", dbh);
  prom_metric_add_counter(metric, "total", "Number of refused connections");
  res = prom_registry_add_metric(prometheus_registry, metric);
  if (res < 0) {
    pr_trace_msg(trace_channel, 1, "error registering metric '%s': %s",
      prom_metric_get_name(metric), strerror(errno));
  }

  metric = prom_metric_create(prometheus_pool, "log_message", dbh);
  prom_metric_add_counter(metric, "total", "Number of log_messages");
  res = prom_registry_add_metric(prometheus_registry, metric);
  if (res < 0) {
    pr_trace_msg(trace_channel, 1, "error registering metric '%s': %s",
      prom_metric_get_name(metric), strerror(errno));
  }

  metric = prom_metric_create(prometheus_pool, "segfault", dbh);
  prom_metric_add_counter(metric, "total", "Number of segfaults");
  res = prom_registry_add_metric(prometheus_registry, metric);
  if (res < 0) {
    pr_trace_msg(trace_channel, 1, "error registering metric '%s': %s",
      prom_metric_get_name(metric), strerror(errno));
  }
}

static void create_metrics(struct prom_dbh *dbh) {
  pool *tmp_pool;
  int res;
  struct prom_metric *metric;

  tmp_pool = make_sub_pool(prometheus_pool);
  pr_pool_tag(tmp_pool, "Prometheus metrics creation pool");

  metric = prom_metric_create(prometheus_pool, "build_info", dbh);
  prom_metric_add_counter(metric, NULL, "ProFTPD build information");
  res = prom_registry_add_metric(prometheus_registry, metric);
  if (res < 0) {
    pr_trace_msg(trace_channel, 1, "error registering metric '%s': %s",
      prom_metric_get_name(metric), strerror(errno));

  } else {
    pr_table_t *labels;

    labels = pr_table_nalloc(tmp_pool, 0, 2);
    (void) pr_table_add_dup(labels, "proftpd_version", pr_version_get_str(), 0);
    (void) pr_table_add_dup(labels, "mod_prometheus_version",
      MOD_PROMETHEUS_VERSION, 0);

    res = prom_metric_incr(tmp_pool, metric, 1, labels);
    if (res <  0) {
      pr_trace_msg(trace_channel, 3, "error incrementing metric '%s': %s",
        prom_metric_get_name(metric), strerror(errno));
    }
  }

  metric = prom_metric_create(prometheus_pool, "startup_time", dbh);
  prom_metric_add_counter(metric, NULL,
    "ProFTPD startup time, in unixtime seconds");
  res = prom_registry_add_metric(prometheus_registry, metric);
  if (res < 0) {
    pr_trace_msg(trace_channel, 1, "error registering metric '%s': %s",
      prom_metric_get_name(metric), strerror(errno));

  } else {
    time_t now;

    now = time(NULL);
    res = prom_metric_incr(tmp_pool, metric, now, NULL);
    if (res <  0) {
      pr_trace_msg(trace_channel, 3, "error incrementing metric '%s': %s",
        prom_metric_get_name(metric), strerror(errno));
    }
  }

  create_server_metrics(tmp_pool, dbh);
  create_session_metrics(tmp_pool, dbh);

  res = prom_registry_sort_metrics(prometheus_registry);
  if (res < 0) {
    pr_trace_msg(trace_channel, 3, "error sorting registry metrics: %s",
      strerror(errno));
  }

  destroy_pool(tmp_pool);
}

static void prom_postparse_ev(const void *event_data, void *user_data) {
  config_rec *c;
  pr_netaddr_t *exporter_addr;
  const char *exporter_username, *exporter_password;

  c = find_config(main_server->conf, CONF_PARAM, "PrometheusEngine", FALSE);
  if (c != NULL) {
    prometheus_engine = *((int *) c->argv[0]);
  }

  if (prometheus_engine == FALSE) {
    return;
  }

  prom_openlog();

  c = find_config(main_server->conf, CONF_PARAM, "PrometheusOptions", FALSE);
  while (c != NULL) {
    unsigned long opts = 0;

    pr_signals_handle();

    opts = *((unsigned long *) c->argv[0]);
    prometheus_opts |= opts;

    c = find_config_next(c, c->next, CONF_PARAM, "PrometheusOptions", FALSE);
  }

  c = find_config(main_server->conf, CONF_PARAM, "PrometheusTables", FALSE);
  if (c == NULL) {
    /* No PrometheusTables configured, mod_prometheus cannot run. */
    (void) pr_log_writefile(prometheus_logfd, MOD_PROMETHEUS_VERSION,
      "no PrometheusTables configured, disabling module");

    prometheus_engine = FALSE;
    return;
  }

  prometheus_tables_dir = c->argv[0];
  prometheus_dbh = prom_metric_init(prometheus_pool, prometheus_tables_dir);
  if (prometheus_dbh == NULL) {
    pr_log_pri(PR_LOG_WARNING, MOD_PROMETHEUS_VERSION
      ": unable to initialize metrics, failing to start up: %s",
      strerror(errno));
    pr_session_disconnect(&prometheus_module, PR_SESS_DISCONNECT_BAD_CONFIG,
      "Failed metrics initialization");
  }

  prometheus_registry = prom_registry_init(prometheus_pool, "proftpd");

  /* Create our known metrics, and register them. */
  create_metrics(prometheus_dbh);

  c = find_config(main_server->conf, CONF_PARAM, "PrometheusExporter", FALSE);
  if (c == NULL) {
    prometheus_engine = FALSE;
    pr_log_debug(DEBUG0, MOD_PROMETHEUS_VERSION
      ": missing required PrometheusExporter directive, disabling module");

    prom_metric_free(prometheus_pool, prometheus_dbh);
    prometheus_dbh = NULL;

    prom_registry_free(prometheus_registry);
    prometheus_registry = NULL;

    return;
  }

  if (prom_http_init(prometheus_pool) < 0) {
    prom_metric_free(prometheus_pool, prometheus_dbh);
    prometheus_dbh = NULL;

    prom_registry_free(prometheus_registry);
    prometheus_registry = NULL;

    pr_log_pri(PR_LOG_ERR, MOD_PROMETHEUS_VERSION
      ": unable to initialize HTTP API, failing to start up: %s",
      strerror(errno));
    pr_session_disconnect(&prometheus_module, PR_SESS_DISCONNECT_BAD_CONFIG,
      "Failed HTTP initialization");
  }

  exporter_addr = c->argv[0];
  exporter_username = c->argv[1];
  exporter_password = c->argv[2];

  /* Look for the exporter credentials environment variables, too. */
  if (exporter_username == NULL) {
    exporter_username = pr_env_get(c->pool, "PROMETHEUS_USERNAME");
    exporter_password = pr_env_get(c->pool, "PROMETHEUS_PASSWORD");
  }

  prometheus_exporter_pid = prom_exporter_start(prometheus_pool, exporter_addr,
    exporter_username, exporter_password);
  if (prometheus_exporter_pid == 0) {
    prometheus_engine = FALSE;
    pr_log_debug(DEBUG0, MOD_PROMETHEUS_VERSION
      ": failed to start exporter process, disabling module");

    prom_metric_free(prometheus_pool, prometheus_dbh);
    prometheus_dbh = NULL;

    prom_registry_free(prometheus_registry);
    prometheus_registry = NULL;
  }
}

static void prom_restart_ev(const void *event_data, void *user_data) {
  if (prometheus_engine == FALSE) {
    return;
  }

  pr_trace_msg(trace_channel, 17,
    "restart event received, resetting counters");

  prom_exporter_stop(prometheus_exporter_pid);

  (void) prom_db_close(prometheus_pool, prometheus_dbh);
  prometheus_dbh = NULL;
  prometheus_exporter_http = NULL;

  (void) prom_registry_free(prometheus_registry);
  prometheus_registry = NULL;
  prometheus_tables_dir = NULL;

  /* Close the PrometheusLog file descriptor; it will be reopened in the
   * postparse event listener.
   */
  (void) close(prometheus_logfd);
  prometheus_logfd = -1;
}

static void prom_shutdown_ev(const void *event_data, void *user_data) {
  prom_exporter_stop(prometheus_exporter_pid);

  (void) prom_db_close(prometheus_pool, prometheus_dbh);
  prometheus_dbh = NULL;

  destroy_pool(prometheus_pool);
  prometheus_pool = NULL;

  (void) close(prometheus_logfd);
  prometheus_logfd = -1;
}

static void prom_startup_ev(const void *event_data, void *user_data) {
  if (prometheus_engine == FALSE) {
    return;
  }

  if (ServerType == SERVER_INETD) {
    pr_log_debug(DEBUG0, MOD_PROMETHEUS_VERSION
      ": cannot support Prometheus for ServerType inetd, disabling module");
    prometheus_engine = FALSE;
    return;
  }
}

static void prom_timeout_idle_ev(const void *event_data, void *user_data) {
  if (prometheus_engine == FALSE) {
    return;
  }

  prom_event_incr("timeout", 1, "reason", "TimeoutIdle", NULL);
}

static void prom_timeout_login_ev(const void *event_data, void *user_data) {
  if (prometheus_engine == FALSE) {
    return;
  }

  prom_event_incr("timeout", 1, "reason", "TimeoutLogin", NULL);
}

static void prom_timeout_noxfer_ev(const void *event_data, void *user_data) {
  if (prometheus_engine == FALSE) {
    return;
  }

  prom_event_incr("timeout", 1, "reason", "TimeoutNoTransfer", NULL);
}

static void prom_timeout_session_ev(const void *event_data, void *user_data) {
  if (prometheus_engine == FALSE) {
    return;
  }

  prom_event_incr("timeout", 1, "reason", "TimeoutSession", NULL);
}

static void prom_timeout_stalled_ev(const void *event_data, void *user_data) {
  if (prometheus_engine == FALSE) {
    return;
  }

  prom_event_incr("timeout", 1, "reason", "TimeoutStalled", NULL);
}

/* mod_tls-generated events */
static void prom_tls_ctrl_handshake_err_ev(const void *event_data,
    void *user_data) {
  if (prometheus_engine == FALSE) {
    return;
  }

  /* Note that we explicitly set the "protocol" label here to "ftps".
   * Otherwise, it would show up as "ftp", since the TLS handshake did
   * not actually succeed, and that "ftp" label would be surprising.
   */
  prom_event_incr("handshake_error", 1, "connection", "ctrl",
    "protocol", "ftps", NULL);
}

static void prom_tls_data_handshake_err_ev(const void *event_data,
    void *user_data) {
  if (prometheus_engine == FALSE) {
    return;
  }
  
  prom_event_incr("handshake_error", 1, "connection", "data", NULL);
}

/* mod_sftp-generated events */
static void prom_ssh2_kex_err_ev(const void *event_data, void *user_data) {
  if (prometheus_engine == FALSE) {
    return;
  }

  prom_event_incr("handshake_error", 1, NULL);
}

static void prom_ssh2_auth_hostbased_ev(const void *event_data,
    void *user_data) {
  if (prometheus_engine == FALSE) {
    return;
  }

  prom_event_incr("auth", 1, "method", "hostbased", NULL);
}

static void prom_ssh2_auth_hostbased_err_ev(const void *event_data,
    void *user_data) {
  if (prometheus_engine == FALSE) {
    return;
  }

  prom_event_incr("auth_error", 1, "method", "hostbased", NULL);
}

static void prom_ssh2_auth_kbdint_ev(const void *event_data,
    void *user_data) {
  if (prometheus_engine == FALSE) {
    return;
  }

  prom_event_incr("auth", 1, "method", "keyboard-interactive", NULL);
}

static void prom_ssh2_auth_kbdint_err_ev(const void *event_data,
    void *user_data) {
  if (prometheus_engine == FALSE) {
    return;
  }

  prom_event_incr("auth_error", 1, "method", "keyboard-interactive", NULL);
}

static void prom_ssh2_auth_passwd_ev(const void *event_data,
    void *user_data) {
  if (prometheus_engine == FALSE) {
    return;
  }

  prom_event_incr("auth", 1, "method", "password", NULL);
}

static void prom_ssh2_auth_passwd_err_ev(const void *event_data,
    void *user_data) {
  if (prometheus_engine == FALSE) {
    return;
  }

  prom_event_incr("auth_error", 1, "method", "password", NULL);
}

static void prom_ssh2_auth_publickey_ev(const void *event_data,
    void *user_data) {
  if (prometheus_engine == FALSE) {
    return;
  }

  prom_event_incr("auth", 1, "method", "publickey", NULL);
}

static void prom_ssh2_auth_publickey_err_ev(const void *event_data,
    void *user_data) {
  if (prometheus_engine == FALSE) {
    return;
  }

  prom_event_incr("auth_error", 1, "method", "publickey", NULL);
}

static void prom_ssh2_sftp_proto_version_ev(const void *event_data,
    void *user_data) {
  unsigned long protocol_version;

  if (prometheus_engine == FALSE) {
    return;
  }

  if (event_data == NULL) {
    /* Missing required data. */
    return;
  }

  protocol_version = *((unsigned long *) event_data);

  switch (protocol_version) {
    case 3:
      prom_event_incr("sftp_protocol", 1, "version", "3", NULL);
      break;

    case 4:
      prom_event_incr("sftp_protocol", 1, "version", "4", NULL);
      break;

    case 5:
      prom_event_incr("sftp_protocol", 1, "version", "5", NULL);
      break;

    case 6:
      prom_event_incr("sftp_protocol", 1, "version", "6", NULL);
      break;

    default:
      (void) pr_log_writefile(prometheus_logfd, MOD_PROMETHEUS_VERSION,
        "unknown SFTP protocol version %lu, ignoring", protocol_version);
  }
}

/* Initialization routines
 */

static int prom_init(void) {
  prometheus_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(prometheus_pool, MOD_PROMETHEUS_VERSION);

  pr_event_register(&prometheus_module, "core.connect", prom_connect_ev, NULL);
#if defined(PR_SHARED_MODULE)
  pr_event_register(&prometheus_module, "core.module-unload",
    prom_mod_unload_ev, NULL);
#endif /* PR_SHARED_MODULE */
  pr_event_register(&prometheus_module, "core.postparse", prom_postparse_ev,
    NULL);
  pr_event_register(&prometheus_module, "core.restart", prom_restart_ev, NULL);
  pr_event_register(&prometheus_module, "core.shutdown", prom_shutdown_ev,
    NULL);
  pr_event_register(&prometheus_module, "core.startup", prom_startup_ev, NULL);

  /* Normally we should register the 'core.exit' event listener in the
   * sess_init callback.  However, we use this listener to listen for
   * refused connections, e.g. connections refused by other modules'
   * sess_init callbacks.  And depending on the module load order, another
   * module might refuse the connection before mod_prometheus's sess_init
   * callback is invoked, which would prevent mod_prometheus from registering
   * its ' core.exit' event listener.
   *
   * Thus to work around this timing issue, we register our 'core.exit' event
   * listener here, in the daemon process.  It should not hurt anything.
   */
  pr_event_register(&prometheus_module, "core.exit", prom_exit_ev, NULL);

#if defined(SQLITE_CONFIG_SINGLETHREAD)
  /* Tell SQLite that we are not a multi-threaded application. */
  sqlite3_config(SQLITE_CONFIG_SINGLETHREAD);
#endif /* SQLITE_CONFIG_SINGLETHREAD */

  return 0;
}

static int prom_sess_init(void) {
  config_rec *c;
  const char *metric_name;
  const struct prom_metric *metric;

  if (prometheus_engine == FALSE) {
    return 0;
  }

  c = find_config(main_server->conf, CONF_PARAM, "PrometheusOptions", FALSE);
  while (c != NULL) {
    unsigned long opts;

    pr_signals_handle();

    opts = *((unsigned long *) c->argv[0]);
    prometheus_opts |= opts;

    c = find_config_next(c, c->next, CONF_PARAM, "PrometheusOptions", FALSE);
  }

  pr_event_register(&prometheus_module, "core.timeout-idle",
    prom_timeout_idle_ev, NULL);
  pr_event_register(&prometheus_module, "core.timeout-login",
    prom_timeout_login_ev, NULL);
  pr_event_register(&prometheus_module, "core.timeout-no-transfer",
    prom_timeout_noxfer_ev, NULL);
  pr_event_register(&prometheus_module, "core.timeout-session",
    prom_timeout_session_ev, NULL);
  pr_event_register(&prometheus_module, "core.timeout-stalled",
    prom_timeout_stalled_ev, NULL);

  pr_event_register(&prometheus_module, "mod_auth.authentication-code",
    prom_auth_code_ev, NULL);

  if (prometheus_opts & PROM_OPT_ENABLE_LOG_MESSAGE_METRICS) {
    pr_event_register(&prometheus_module, "core.log.syslog", prom_log_msg_ev,
      NULL);
    pr_event_register(&prometheus_module, "core.log.systemlog", prom_log_msg_ev,
      NULL);
  }

  if (pr_module_exists("mod_tls.c") == TRUE) {
    /* mod_tls events */
    pr_event_register(&prometheus_module, "mod_tls.ctrl-handshake-failed",
      prom_tls_ctrl_handshake_err_ev, NULL);
    pr_event_register(&prometheus_module, "mod_tls.data-handshake-failed",
      prom_tls_data_handshake_err_ev, NULL);
  }

  if (pr_module_exists("mod_sftp.c") == TRUE) {
    /* mod_sftp events */

    pr_event_register(&prometheus_module, "mod_sftp.ssh2.kex.failed",
      prom_ssh2_kex_err_ev, NULL);

    pr_event_register(&prometheus_module, "mod_sftp.ssh2.auth-hostbased",
      prom_ssh2_auth_hostbased_ev, NULL);
    pr_event_register(&prometheus_module, "mod_sftp.ssh2.auth-hostbased.failed",
      prom_ssh2_auth_hostbased_err_ev, NULL);

    pr_event_register(&prometheus_module, "mod_sftp.ssh2.auth-kbdint",
      prom_ssh2_auth_kbdint_ev, NULL);
    pr_event_register(&prometheus_module, "mod_sftp.ssh2.auth-kbdint.failed",
      prom_ssh2_auth_kbdint_err_ev, NULL);

    pr_event_register(&prometheus_module, "mod_sftp.ssh2.auth-password",
      prom_ssh2_auth_passwd_ev, NULL);
    pr_event_register(&prometheus_module, "mod_sftp.ssh2.auth-password.failed",
      prom_ssh2_auth_passwd_err_ev, NULL);

    pr_event_register(&prometheus_module, "mod_sftp.ssh2.auth-publickey",
      prom_ssh2_auth_publickey_ev, NULL);
    pr_event_register(&prometheus_module, "mod_sftp.ssh2.auth-publickey.failed",
      prom_ssh2_auth_publickey_err_ev, NULL);

    pr_event_register(&prometheus_module, "mod_sftp.sftp.protocol-version",
      prom_ssh2_sftp_proto_version_ev, NULL);
  }

  metric_name = "connection";
  metric = prom_registry_get_metric(prometheus_registry, metric_name);
  if (metric != NULL) {
    pool *tmp_pool;
    pr_table_t *labels;

    pr_gettimeofday_millis(&prometheus_connected_ms);

    tmp_pool = make_sub_pool(session.pool);
    labels = prom_get_labels(tmp_pool);
    prom_metric_incr(tmp_pool, metric, 1, labels);
    destroy_pool(tmp_pool);

  } else {
    pr_trace_msg(trace_channel, 19, "CONNECT: unknown '%s' metric requested",
      metric_name);
  }

  return 0;
}

/* Module API tables
 */

static conftable prometheus_conftab[] = {
  { "PrometheusEngine",		set_prometheusengine,		NULL },
  { "PrometheusExporter",	set_prometheusexporter,		NULL },
  { "PrometheusLog",		set_prometheuslog,		NULL },
  { "PrometheusOptions",	set_prometheusoptions,		NULL },
  { "PrometheusTables",		set_prometheustables,		NULL },
  { NULL }
};

static cmdtable prometheus_cmdtab[] = {
  { PRE_CMD,		C_LIST,	G_NONE,	prom_pre_list,	FALSE,	FALSE },
  { LOG_CMD,		C_LIST,	G_NONE,	prom_log_list,	FALSE,	FALSE },
  { LOG_CMD_ERR,	C_LIST,	G_NONE,	prom_err_list,	FALSE,	FALSE },

  { PRE_CMD,		C_MLSD,	G_NONE,	prom_pre_list,	FALSE,	FALSE },
  { LOG_CMD,		C_MLSD,	G_NONE,	prom_log_list,	FALSE,	FALSE },
  { LOG_CMD_ERR,	C_MLSD,	G_NONE,	prom_err_list,	FALSE,	FALSE },

  { PRE_CMD,		C_MLST,	G_NONE,	prom_pre_list,	FALSE,	FALSE },
  { LOG_CMD,		C_MLST,	G_NONE,	prom_log_list,	FALSE,	FALSE },
  { LOG_CMD_ERR,	C_MLST,	G_NONE,	prom_err_list,	FALSE,	FALSE },

  { PRE_CMD,		C_NLST,	G_NONE,	prom_pre_list,	FALSE,	FALSE },
  { LOG_CMD,		C_NLST,	G_NONE,	prom_log_list,	FALSE,	FALSE },
  { LOG_CMD_ERR,	C_NLST,	G_NONE,	prom_err_list,	FALSE,	FALSE },

  { PRE_CMD,		C_USER, G_NONE, prom_pre_user,	FALSE,	FALSE },
  { LOG_CMD_ERR,	C_USER, G_NONE, prom_err_login,	FALSE,	FALSE },
  { PRE_CMD,		C_PASS, G_NONE, prom_pre_pass,	FALSE,	FALSE },
  { LOG_CMD,		C_PASS,	G_NONE,	prom_log_pass,	FALSE,	FALSE },
  { LOG_CMD_ERR,	C_PASS,	G_NONE,	prom_err_login,	FALSE,	FALSE },

  { PRE_CMD,		C_RETR,	G_NONE,	prom_pre_retr,	FALSE,	FALSE },
  { LOG_CMD,		C_RETR,	G_NONE,	prom_log_retr,	FALSE,	FALSE },
  { LOG_CMD_ERR,	C_RETR,	G_NONE,	prom_err_retr,	FALSE,	FALSE },

  { PRE_CMD,		C_STOR,	G_NONE,	prom_pre_stor,	FALSE,	FALSE },
  { LOG_CMD,		C_STOR,	G_NONE,	prom_log_stor,	FALSE,	FALSE },
  { LOG_CMD_ERR,	C_STOR,	G_NONE,	prom_err_stor,	FALSE,	FALSE },

  /* For mod_tls */
  { LOG_CMD,		C_AUTH,	G_NONE,	prom_log_auth,	FALSE,	FALSE },

  { 0, NULL }
};

module prometheus_module = {
  /* Always NULL */
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "prometheus",

  /* Module configuration handler table */
  prometheus_conftab,

  /* Module command handler table */
  prometheus_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization */
  prom_init,

  /* Session initialization */
  prom_sess_init,

  /* Module version */
  MOD_PROMETHEUS_VERSION
};
