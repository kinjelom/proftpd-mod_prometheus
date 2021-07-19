/*
 * ProFTPD - mod_prometheus
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
 *
 * -----DO NOT EDIT BELOW THIS LINE-----
 * $Archive: mod_prometheus.a $
 * $Libraries: -lmicrohttpd -lsqlite3$
 */

#include "mod_prometheus.h"
#include "prometheus/db.h"
#include "prometheus/registry.h"
#include "prometheus/metric.h"
#include "prometheus/http.h"

/* Defaults */
#define PROMETHEUS_DEFAULT_EXPORTER_PORT	9273

extern xaset_t *server_list;

int prometheus_logfd = -1;
module prometheus_module;
pool *prometheus_pool = NULL;

static int prometheus_engine = FALSE;
static unsigned long prometheus_opts = 0UL;
static struct timeval prometheus_start_tv;
static const char *prometheus_tables_dir = NULL;

static struct prom_registry *prometheus_registry = NULL;
static struct prom_http *prometheus_exporter_http = NULL;
static pid_t prometheus_exporter_pid = 0;

/* Number of seconds to wait for the exporter process to stop before
 * we terminate it with extreme prejudice.
 *
 * Currently this has a granularity of seconds; needs to be in millsecs
 * (e.g. for 500 ms timeout).
 */
static time_t prometheus_exporter_timeout = 1;

/* Used for tracking download, upload byte totals. */
static off_t prometheus_retr_bytes = 0, prometheus_stor_bytes = 0;

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

static pid_t prom_exporter_start(pool *p, unsigned short exporter_port) {
  pid_t exporter_pid;
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

  prometheus_exporter_http = prom_http_start(p, exporter_port);
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

/* usage: PrometheusExporter [address:]port */
MODRET set_prometheusexporter(cmd_rec *cmd) {
  char *ptr;
  config_rec *c;
  unsigned short exporter_port = PROMETHEUS_DEFAULT_EXPORTER_PORT;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  /* Separate the port out from the address, if present. */
  ptr = strrchr(cmd->argv[1], ':');
  if (ptr != NULL) {
    /* XXX Handle provided address; deal with libmicrohttpd API for
     * assigning/binding to specific listening address.
     *
     * Handle both IPv4 and IPv6 addresses.
     */

  } else {
    int port;

    port = atoi(cmd->argv[1]);
    if (port < 1 || port > 65535) {
      CONF_ERROR(cmd, "port must be between 1-65535");
    }

    exporter_port = (unsigned short) port;
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned short));
  *((unsigned short *) c->argv[0]) = exporter_port;
 
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
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown PrometheusOption '",
      cmd->argv[i], "'", NULL));
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

MODRET prom_pre_list(cmd_rec *cmd) {
  const char *proto;

  if (prometheus_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  proto = pr_session_get_protocol(0);
  return PR_DECLINED(cmd);
}

MODRET prom_log_list(cmd_rec *cmd) {
  const char *proto;

  if (prometheus_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  proto = pr_session_get_protocol(0);
  return PR_DECLINED(cmd);
}

MODRET prom_err_list(cmd_rec *cmd) {
  const char *proto;

  if (prometheus_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  proto = pr_session_get_protocol(0);
  return PR_DECLINED(cmd);
}

MODRET prom_log_pass(cmd_rec *cmd) {
  const char *proto; 

  if (prometheus_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  proto = pr_session_get_protocol(0);
  return PR_DECLINED(cmd);
}

MODRET prom_err_pass(cmd_rec *cmd) {
  const char *proto;

  if (prometheus_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  proto = pr_session_get_protocol(0);
  return PR_DECLINED(cmd);
}

MODRET prom_pre_retr(cmd_rec *cmd) {
  const char *proto;

  if (prometheus_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  proto = pr_session_get_protocol(0);
  return PR_DECLINED(cmd);
}

MODRET prom_log_retr(cmd_rec *cmd) {
  const char *proto;
  uint32_t retr_kb;
  off_t rem_bytes;

  if (prometheus_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  proto = pr_session_get_protocol(0);

  /* We also need to increment the KB download count.  We know the number
   * of bytes downloaded as an off_t here, but we only store the number of KB
   * in the mod_prometheus db tables.
   * 
   * We could just increment by xfer_bytes / 1024, but that would mean that
   * several small files of say 999 bytes could be downloaded, and the KB
   * count would not be incremented.
   *
   * To deal with this situation, we use the prometheus_retr_bytes static
   * variable as a "holding bucket" of bytes, from which we get the KB to add
   * to the db tables.
   */
  prometheus_retr_bytes += session.xfer.total_bytes;

  retr_kb = (prometheus_retr_bytes / 1024);
  rem_bytes = (prometheus_retr_bytes % 1024);

  prometheus_retr_bytes = rem_bytes;
  return PR_DECLINED(cmd);
}

MODRET prom_err_retr(cmd_rec *cmd) {
  const char *proto;

  if (prometheus_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  proto = pr_session_get_protocol(0);
  return PR_DECLINED(cmd);
}

MODRET prom_pre_stor(cmd_rec *cmd) {
  const char *proto;

  if (prometheus_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  proto = pr_session_get_protocol(0);
  return PR_DECLINED(cmd);
}

MODRET prom_log_stor(cmd_rec *cmd) {
  const char *proto;
  uint32_t stor_kb;
  off_t rem_bytes;

  if (prometheus_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  proto = pr_session_get_protocol(0);

  /* We also need to increment the KB upload count.  We know the number
   * of bytes downloaded as an off_t here, but we only store the number of KB
   * in the mod_prometheus db tables.
   * 
   * We could just increment by xfer_bytes / 1024, but that would mean that
   * several small files of say 999 bytes could be uploaded, and the KB
   * count would not be incremented.
   *
   * To deal with this situation, we use the prometheus_stor_bytes static
   * variable as a "holding bucket" of bytes, from which we get the KB to add
   * to the db tables.
   */
  prometheus_stor_bytes += session.xfer.total_bytes;

  stor_kb = (prometheus_stor_bytes / 1024);
  rem_bytes = (prometheus_stor_bytes % 1024);

  prometheus_stor_bytes = rem_bytes;
  return PR_DECLINED(cmd);
}

MODRET prom_err_stor(cmd_rec *cmd) {
  const char *proto;

  if (prometheus_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  proto = pr_session_get_protocol(0);
  return PR_DECLINED(cmd);
}

MODRET prom_log_auth(cmd_rec *cmd) {
  const char *proto;

  if (prometheus_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  /* Note: we are not currently properly incrementing
   * session_count/session_total{protocol="ftps"} for FTPS connections
   * accepted using the UseImplicitSSL TLSOption.
   *
   * The issue is that for those connections, the protocol will be set to
   * "ftps" in mod_tls' sess_init callback.  But here in mod_prometheus, we
   * are not guaranteed to being called AFTER mod_tls, due to module load
   * ordering.  Thus we do not have a good way of determining when to
   * increment those counts for implicit FTPS connections.
   */

  proto = pr_session_get_protocol(0);
  return PR_DECLINED(cmd);
}

/* Event listeners
 */

static void ev_incr_value(const char *metric_name, int32_t incr,
    pr_table_t *labels) {
  int res;
  pool *p;
  const struct prom_metric *metric;

  p = session.pool;
  if (p == NULL) {
    p = prometheus_pool;
  }

  metric = prom_registry_get_metric(prometheus_registry, metric_name);
  if (metric == NULL) {
    pr_trace_msg(trace_channel, 17, "unknown metric name '%s' requested",
      metric_name);
    return;
  }

/* XXX need to add protocol label, others */
  res = prom_metric_incr_value(p, metric, incr, labels);
  if (res < 0) {
    (void) pr_log_writefile(prometheus_logfd, MOD_PROMETHEUS_VERSION,
      "error %s %s: %s",
      incr < 0 ? "decrementing" : "incrementing", metric_name,
      strerror(errno));
  }
}

static void prom_auth_code_ev(const void *event_data, void *user_data) {
  int auth_code;
  const char *metric_name = NULL;
  pr_table_t *labels = NULL;

  if (prometheus_engine == FALSE) {
    return;
  }

  auth_code = *((int *) event_data);

  switch (auth_code) {
    case PR_AUTH_RFC2228_OK:
      metric_name = "login_total";
      /* pr_table_add(labels, "method", "certificate") */
      break;

    case PR_AUTH_OK:
      metric_name = "login_total";
      break;

    case PR_AUTH_NOPWD:
      metric_name = "login_err_total";
      /* pr_table_add(labels, "reason", "unknown user") */
      break;

    case PR_AUTH_BADPWD:
      metric_name = "login_err_total";
      /* pr_table_add(labels, "reason", "bad password") */
      break;

    default:
      metric_name = "login_err_total";
      break;
  }
 
  ev_incr_value(metric_name, 1, labels); 
}

static void prom_cmd_invalid_ev(const void *event_data, void *user_data) {
  const char *metric_name;

  if (prometheus_engine == FALSE) {
    return;
  }

  metric_name = "invalid_command_total";  
  ev_incr_value(metric_name, 1, NULL);
}

static void prom_exit_ev(const void *event_data, void *user_data) {
  pr_table_t *labels = NULL;

  if (prometheus_engine == FALSE) {
    return;
  }

  ev_incr_value("connection_count", -1, NULL);

  switch (session.disconnect_reason) {
    case PR_SESS_DISCONNECT_BANNED:
    case PR_SESS_DISCONNECT_CONFIG_ACL:
    case PR_SESS_DISCONNECT_MODULE_ACL:
    case PR_SESS_DISCONNECT_SESSION_INIT_FAILED:
      /* XXX Add labels for refusal reason? */
      ev_incr_value("connection_refused_total", 1, NULL);
      break;

    case PR_SESS_DISCONNECT_SEGFAULT:
      ev_incr_value("segfault_total", 1, NULL);
      break;

    default: {
      const char *proto;

      proto = pr_session_get_protocol(0);

      ev_incr_value("session_count", -1, NULL);
      ev_incr_value("session_total", 1, NULL);

      if (strcmp(proto, "ftp") == 0 &&
          session.anon_config != NULL) {
        /* XXX pr_table_add(labels, "method", "anonymous") */
        ev_incr_value("login_count", -1, labels);
      }

      break;
    }
  }

  prom_http_free();

  if (prometheus_logfd >= 0) {
    (void) close(prometheus_logfd);
    prometheus_logfd = -1;
  }
}

#if defined(PR_SHARED_MODULE)
static void prom_mod_unload_ev(const void *event_data, void *user_data) {
  register unsigned int i;

  if (strcmp((const char *) event_data, "mod_prometheus.c") != 0) {
    return;
  }

  /* Unregister ourselves from all events. */
  pr_event_unregister(&prometheus_module, NULL, NULL);

  /* XXX Need to close various database tables here. */

  destroy_pool(prometheus_pool);
  prometheus_pool = NULL;

  (void) close(prometheus_logfd);
  prometheus_logfd = -1;

  prometheus_exporter_http = NULL;
  prometheus_registry = NULL;
  prometheus_tables_dir = NULL;
}
#endif /* PR_SHARED_MODULE */

static void prom_postparse_ev(const void *event_data, void *user_data) {
  config_rec *c;
  int exporter_port;

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

  prometheus_registry = prom_registry_init(prometheus_pool);

  if (prom_metric_init(prometheus_pool, prometheus_tables_dir,
      prometheus_registry) < 0) {
    pr_log_pri(PR_LOG_WARNING, MOD_PROMETHEUS_VERSION
      ": unable to initialize metrics, failing to start up: %s",
      strerror(errno));
    pr_session_disconnect(&prometheus_module, PR_SESS_DISCONNECT_BAD_CONFIG,
      "Failed metrics initialization");
  }

  c = find_config(main_server->conf, CONF_PARAM, "PrometheusExporter", FALSE);
  if (c == NULL) {
    prometheus_engine = FALSE;
    pr_log_debug(DEBUG0, MOD_PROMETHEUS_VERSION
      ": missing required PrometheusExporter directive, disabling module");

    prom_metric_free(prometheus_pool);
    prom_registry_free(prometheus_registry);
    prometheus_registry = NULL;

    return;
  }

  if (prom_http_init(prometheus_pool) < 0) {
    prom_metric_free(prometheus_pool);
    prom_registry_free(prometheus_registry);
    prometheus_registry = NULL;

    pr_log_pri(PR_LOG_ERR, MOD_PROMETHEUS_VERSION
      ": unable to initialize HTTP API, failing to start up: %s",
      strerror(errno));
    pr_session_disconnect(&prometheus_module, PR_SESS_DISCONNECT_BAD_CONFIG,
      "Failed HTTP initialization");
  }

  exporter_port = *((unsigned short *) c->argv[0]);

  prometheus_exporter_pid = prom_exporter_start(prometheus_pool, exporter_port);
  if (prometheus_exporter_pid == 0) {
    prometheus_engine = FALSE;
    pr_log_debug(DEBUG0, MOD_PROMETHEUS_VERSION
      ": failed to start exporter process, disabling module");

    prom_metric_free(prometheus_pool);
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
  /* XXX */

  prom_exporter_stop(prometheus_exporter_pid);

  /* Close the PrometheusLog file descriptor; it will be reopened in the
   * postparse event listener.
   */
  (void) close(prometheus_logfd);
  prometheus_logfd = -1;
}

static void prom_shutdown_ev(const void *event_data, void *user_data) {
  prom_exporter_stop(prometheus_exporter_pid);

  /* XXX Need to close various database tables here. */

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

/* XXX Add build_info metric, start_timestamp */
  gettimeofday(&prometheus_start_tv, NULL);
}

static void prom_timeout_idle_ev(const void *event_data, void *user_data) {
  pr_table_t *labels = NULL;

  if (prometheus_engine == FALSE) {
    return;
  }

/* XXX pr_table_add(labels, "reason", "idle") */
  ev_incr_value("timeout_total", 1, labels);
}

static void prom_timeout_login_ev(const void *event_data, void *user_data) {
  pr_table_t *labels = NULL;

  if (prometheus_engine == FALSE) {
    return;
  }

/* XXX pr_table_add(labels, "reason", "login") */
  ev_incr_value("timeout_total", 1, labels);
}

static void prom_timeout_noxfer_ev(const void *event_data, void *user_data) {
  pr_table_t *labels = NULL;

  if (prometheus_engine == FALSE) {
    return;
  }

/* XXX pr_table_add(labels, "reason", "notransfer") */
  ev_incr_value("timeout_total", 1, labels);
}

static void prom_timeout_stalled_ev(const void *event_data, void *user_data) {
  pr_table_t *labels = NULL;

  if (prometheus_engine == FALSE) {
    return;
  }

/* XXX pr_table_add(labels, "reason", "stalled") */
  ev_incr_value("timeout_total", 1, labels);
}

/* mod_tls-generated events */
static void prom_tls_ctrl_handshake_err_ev(const void *event_data,
    void *user_data) {
  pr_table_t *labels = NULL;

  if (prometheus_engine == FALSE) {
    return;
  }

/* XXX pr_table_add(labels, "connection", "ctrl") */
  ev_incr_value("handshake_error_total", 1, labels);
}

static void prom_tls_data_handshake_err_ev(const void *event_data,
    void *user_data) {
  pr_table_t *labels = NULL;

  if (prometheus_engine == FALSE) {
    return;
  }
  
/* XXX pr_table_add(labels, "connection", "data") */
  ev_incr_value("handshake_error_total", 1, labels);
}

/* mod_sftp-generated events */
static void prom_ssh2_kex_err_ev(const void *event_data, void *user_data) {
  if (prometheus_engine == FALSE) {
    return;
  }

  ev_incr_value("handshake_error_total", 1, NULL);
}

static void prom_ssh2_auth_hostbased_ev(const void *event_data,
    void *user_data) {
  pr_table_t *labels = NULL;

  if (prometheus_engine == FALSE) {
    return;
  }

/* XXX pr_table_add(labels, "method", "hostbased") */
  ev_incr_value("login_count", 1, labels);
  ev_incr_value("login_total", 1, labels);
}

static void prom_ssh2_auth_hostbased_err_ev(const void *event_data,
    void *user_data) {
  pr_table_t *labels = NULL;

  if (prometheus_engine == FALSE) {
    return;
  }

/* XXX pr_table_add(labels, "method", "hostbased") */
  ev_incr_value("login_error_total", 1, labels);
}

static void prom_ssh2_auth_kbdint_ev(const void *event_data,
    void *user_data) {
  pr_table_t *labels = NULL;

  if (prometheus_engine == FALSE) {
    return;
  }

/* XXX pr_table_add(labels, "method", "keyboard-interactive") */
  ev_incr_value("login_count", 1, labels);
  ev_incr_value("login_total", 1, labels);
}

static void prom_ssh2_auth_kbdint_err_ev(const void *event_data,
    void *user_data) {
  pr_table_t *labels = NULL;

  if (prometheus_engine == FALSE) {
    return;
  }

/* XXX pr_table_add(labels, "method", "keyboard-interactive") */
  ev_incr_value("login_error_total", 1, labels);
}

static void prom_ssh2_auth_passwd_ev(const void *event_data,
    void *user_data) {
  pr_table_t *labels = NULL;

  if (prometheus_engine == FALSE) {
    return;
  }

/* XXX pr_table_add(labels, "method", "password") */
  ev_incr_value("login_count", 1, labels);
  ev_incr_value("login_total", 1, labels);
}

static void prom_ssh2_auth_passwd_err_ev(const void *event_data,
    void *user_data) {
  pr_table_t *labels = NULL;

  if (prometheus_engine == FALSE) {
    return;
  }

/* XXX pr_table_add(labels, "method", "password") */
  ev_incr_value("login_error_total", 1, labels);
}

static void prom_ssh2_auth_publickey_ev(const void *event_data,
    void *user_data) {
  pr_table_t *labels = NULL;

  if (prometheus_engine == FALSE) {
    return;
  }

/* XXX pr_table_add(labels, "method", "publickey") */
  ev_incr_value("login_count", 1, labels);
  ev_incr_value("login_total", 1, labels);
}

static void prom_ssh2_auth_publickey_err_ev(const void *event_data,
    void *user_data) {
  pr_table_t *labels = NULL;

  if (prometheus_engine == FALSE) {
    return;
  }

/* XXX pr_table_add(labels, "method", "publickey") */
  ev_incr_value("login_error_total", 1, labels);
}

static void prom_ssh2_sftp_proto_version_ev(const void *event_data,
    void *user_data) {
  unsigned long protocol_version;
  pr_table_t *labels = NULL;

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
      /* XXX pr_table_add(labels, "version", "3") */
      break;

    case 4:
      /* XXX pr_table_add(labels, "version", "4") */
      break;

    case 5:
      /* XXX pr_table_add(labels, "version", "5") */
      break;

    case 6:
      /* XXX pr_table_add(labels, "version", "6") */
      break;

    default:
      (void) pr_log_writefile(prometheus_logfd, MOD_PROMETHEUS_VERSION,
        "unknown SFTP protocol version %lu, ignoring", protocol_version);
      return;
  }

  ev_incr_value("sftp_protocol_total", 1, labels);
}

static void prom_ssh2_sftp_sess_opened_ev(const void *event_data,
    void *user_data) {
  if (prometheus_engine == FALSE) {
    return;
  }

  ev_incr_value("session_count", 1, NULL);
  ev_incr_value("session_total", 1, NULL);
}

static void prom_ssh2_sftp_sess_closed_ev(const void *event_data,
    void *user_data) {
  if (prometheus_engine == FALSE) {
    return;
  }

  ev_incr_value("session_count", -1, NULL);
}

static void prom_ssh2_scp_sess_opened_ev(const void *event_data,
    void *user_data) {
  if (prometheus_engine == FALSE) {
    return;
  }

  ev_incr_value("session_count", 1, NULL);
  ev_incr_value("session_total", 1, NULL);
}

static void prom_ssh2_scp_sess_closed_ev(const void *event_data,
    void *user_data) {
  if (prometheus_engine == FALSE) {
    return;
  }

  ev_incr_value("session_count", -1, NULL);
}

/* Initialization routines
 */

static int prom_init(void) {
  prometheus_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(prometheus_pool, MOD_PROMETHEUS_VERSION);

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
   * module might refuse the connection before mod_snmp's sess_init callback
   * is invoked, which would prevent mod_prometheus from registering its
   * 'core.exit' event listener.
   *
   * Thus to work around this timing issue, we register our 'core.exit' event
   * listener here, in the daemon process.  It should not hurt anything.
   */
  pr_event_register(&prometheus_module, "core.exit", prom_exit_ev, NULL);

  return 0;
}

static int prom_sess_init(void) {
  pr_event_register(&prometheus_module, "core.invalid-command",
    prom_cmd_invalid_ev, NULL);
  pr_event_register(&prometheus_module, "core.timeout-idle",
    prom_timeout_idle_ev, NULL);
  pr_event_register(&prometheus_module, "core.timeout-login",
    prom_timeout_login_ev, NULL);
  pr_event_register(&prometheus_module, "core.timeout-no-transfer",
    prom_timeout_noxfer_ev, NULL);
  pr_event_register(&prometheus_module, "core.timeout-stalled",
    prom_timeout_stalled_ev, NULL);
  pr_event_register(&prometheus_module, "core.unhandled-command",
    prom_cmd_invalid_ev, NULL);

  pr_event_register(&prometheus_module, "mod_auth.authentication-code",
    prom_auth_code_ev, NULL);

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

    pr_event_register(&prometheus_module, "mod_sftp.sftp.session-opened",
      prom_ssh2_sftp_sess_opened_ev, NULL);
    pr_event_register(&prometheus_module, "mod_sftp.sftp.session-closed",
      prom_ssh2_sftp_sess_closed_ev, NULL);
    pr_event_register(&prometheus_module, "mod_sftp.sftp.protocol-version",
      prom_ssh2_sftp_proto_version_ev, NULL);

    pr_event_register(&prometheus_module, "mod_sftp.scp.session-opened",
      prom_ssh2_scp_sess_opened_ev, NULL);
    pr_event_register(&prometheus_module, "mod_sftp.scp.session-closed",
      prom_ssh2_scp_sess_closed_ev, NULL);
  }

#if TJ
  res = prom_db_incr_value(session.pool, PROM_DB_DAEMON_F_CONN_COUNT, 1);
  if (res < 0) {
    (void) pr_log_writefile(prometheus_logfd, MOD_PROMETHEUS_VERSION,
      "error incrementing daemon.connectionCount: %s",
      strerror(errno));
  }

  res = prom_db_incr_value(session.pool, PROM_DB_DAEMON_F_CONN_TOTAL, 1);
  if (res < 0) {
    (void) pr_log_writefile(prometheus_logfd, MOD_PROMETHEUS_VERSION,
      "error incrementing daemon.connectionTotal: %s",
      strerror(errno));
  }
#endif

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

  { PRE_CMD,		C_NLST,	G_NONE,	prom_pre_list,	FALSE,	FALSE },
  { LOG_CMD,		C_NLST,	G_NONE,	prom_log_list,	FALSE,	FALSE },
  { LOG_CMD_ERR,	C_NLST,	G_NONE,	prom_err_list,	FALSE,	FALSE },

  { LOG_CMD,		C_PASS,	G_NONE,	prom_log_pass,	FALSE,	FALSE },
  { LOG_CMD_ERR,	C_PASS,	G_NONE,	prom_err_pass,	FALSE,	FALSE },

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
