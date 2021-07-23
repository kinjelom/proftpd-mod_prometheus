package ProFTPD::Tests::Modules::mod_prometheus;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use Data::Dumper;
use File::Path qw(mkpath);
use File::Spec;
use IO::Handle;

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :features :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
  prom_start_existing_dirs => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_unacceptable_method => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_bad_uri => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_base_uri => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_metrics_uri => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  # Basic metrics
  prom_scrape_metric_build_info => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_metric_startup_time => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  # Server metrics
  prom_scrape_metric_connection => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_metric_connection_refused => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_metric_log_message => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  # Session metrics
  prom_scrape_metric_auth_ok => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_metric_auth_anon_ok => {
    order => ++$order,
    test_class => [qw(forking prometheus rootprivs)],
  },

  prom_scrape_metric_auth_unknown_user => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_metric_auth_bad_password => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_metric_auth_error => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_metric_connection => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_metric_directory_list => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_metric_directory_list_error => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_metric_file_download => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_metric_file_download_error => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_metric_file_upload => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_metric_file_upload_error => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  # Pre-login
  # Post-login
  # Multiple login attempts: n USER/PASS.  1 USER, n PASS.
  # Truncated login: USER, QUIT.
  #
  # Make sure gauge decrements for these.
  prom_scrape_metric_login => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  # Failed logins: unknown USER, bad password
  # Blocked logins: <Limit LOGIN>+DenyUser
  prom_scrape_metric_login_error => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  # TODO Move mod_tls/mod_sftp tests into mod_prometheus/tls.pm, /sftp.pm
  # files.

  # TODO: Need multiple tests here, for the timeout-specific labels
  prom_scrape_metric_timeout => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  # TODO: Need multiple tests here, for ctrl/data handshake errors
  prom_scrape_metric_handshake_error_tls => {
    order => ++$order,
    test_class => [qw(forking mod_tls prometheus)],
  },

  prom_scrape_metric_handshake_error_ssh => {
    order => ++$order,
    test_class => [qw(forking mod_sftp prometheus)],
  },

  prom_scrape_metric_tls_protocol => {
    order => ++$order,
    test_class => [qw(forking mod_tls prometheus)],
  },

  prom_scrape_metric_sftp_protocol => {
    order => ++$order,
    test_class => [qw(forking mod_sftp prometheus)],
  },

  prom_config_exporter_addr => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  # Check for the required Perl modules:
  #
  #  LWP-UserAgent

  my $required = [qw(
    LWP::UserAgent
  )];

  foreach my $req (@$required) {
    eval "use $req";
    if ($@) {
      print STDERR "\nWARNING:\n + Module '$req' not found, skipping all tests\n
";

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Unable to load $req: $@\n";
      }

      return qw(testsuite_empty_test);
    }
  }

  # TO ADD:
  #  prom_scrape_metrics_uri_with_basic_auth
  #  prom_scrape_metrics_uri_with_gzip

#  return testsuite_get_runnable_tests($TESTS);
  return qw(
    prom_scrape_metric_auth_anon_ok
  );
#    prom_scrape_metric_auth_unknown_user
#    prom_scrape_metric_auth_bad_password
}

# Support routines

sub saw_expected_content {
  my $lines = shift;
  my $expected = shift;
  my $seen = 0;

  foreach my $line (@$lines) {
    if ($line =~ /$expected/) {
      $seen = 1;
      last;
    }
  }

  return $seen;
}

# Test cases

sub prom_start_existing_dirs {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $table_dir)) {
      die("Can't set perms on $table_dir to 0755: $!");
    }

    unless (chown($setup->{uid}, $setup->{gid}, $table_dir)) {
      die("Can't set owner of $table_dir to $setup->{uid}/$setup->{gid}: $!");
    }
  }

  my $exporter_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'prometheus:20 prometheus.http:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_prometheus.c' => {
        PrometheusEngine => 'on',
        PrometheusLog => $setup->{log_file},
        PrometheusTables => $table_dir,
        PrometheusExporter => "127.0.0.1:$exporter_port",
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  my $ex;

  # First, start the server
  server_start($setup->{config_file});
  
  # ...then stop the server.  This means mod_prometheus will have created all
  # the necessary directories, etc.
  sleep(2);
  server_stop($setup->{pid_file});

  # Now start the server again.  Time time, mod_prometheus will double-check
  # permissions et al on the already-existing mod_prometheus directories that it
  # created the first time.
  sleep(2);
  server_start($setup->{config_file});

  # Stop server
  sleep(2);
  eval { server_stop($setup->{pid_file}) };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub prom_scrape_unacceptable_method {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $table_dir)) {
      die("Can't set perms on $table_dir to 0755: $!");
    }

    unless (chown($setup->{uid}, $setup->{gid}, $table_dir)) {
      die("Can't set owner of $table_dir to $setup->{uid}/$setup->{gid}: $!");
    }
  }

  my $exporter_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Using export port = $exporter_port\n";
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'prometheus:20 prometheus.http:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_prometheus.c' => {
        PrometheusEngine => 'on',
        PrometheusLog => $setup->{log_file},
        PrometheusTables => $table_dir,
        PrometheusExporter => "127.0.0.1:$exporter_port",
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require LWP::UserAgent;

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow server to start up
      sleep(2);

      my $ua = LWP::UserAgent->new();
      $ua->timeout(3);

      my $url = "http://127.0.0.1:$exporter_port/foo/bar/baz";
      my $resp = $ua->delete($url);

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# response: ", $resp->status_line, "\n";
      }

      my $expected = 405;
      my $resp_code = $resp->code;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'Method Not Allowed';
      my $resp_msg = $resp->message;
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      my $headers = $resp->headers;
      my $content_type = $headers->header('Content-Type');
      $expected = 'text/plain';
      $self->assert($expected eq $content_type,
        test_msg("Expected Content-Type '$expected', got '$content_type'"));
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub prom_scrape_bad_uri {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $table_dir)) {
      die("Can't set perms on $table_dir to 0755: $!");
    }

    unless (chown($setup->{uid}, $setup->{gid}, $table_dir)) {
      die("Can't set owner of $table_dir to $setup->{uid}/$setup->{gid}: $!");
    }
  }

  my $exporter_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Using export port = $exporter_port\n";
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'prometheus:20 prometheus.http:20 prometheus.http.clf:10',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_prometheus.c' => {
        PrometheusEngine => 'on',
        PrometheusLog => $setup->{log_file},
        PrometheusTables => $table_dir,
        PrometheusExporter => "127.0.0.1:$exporter_port",
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require LWP::UserAgent;

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow server to start up
      sleep(2);

      my $ua = LWP::UserAgent->new();
      $ua->timeout(3);

      my $url = "http://127.0.0.1:$exporter_port/foo/bar/baz";
      my $resp = $ua->get($url);

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# response: ", $resp->status_line, "\n";
      }

      my $expected = 400;
      my $resp_code = $resp->code;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'Bad Request';
      my $resp_msg = $resp->message;
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      my $headers = $resp->headers;
      my $content_type = $headers->header('Content-Type');
      $expected = 'text/plain';
      $self->assert($expected eq $content_type,
        test_msg("Expected Content-Type '$expected', got '$content_type'"));
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub prom_scrape_base_uri {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $table_dir)) {
      die("Can't set perms on $table_dir to 0755: $!");
    }

    unless (chown($setup->{uid}, $setup->{gid}, $table_dir)) {
      die("Can't set owner of $table_dir to $setup->{uid}/$setup->{gid}: $!");
    }
  }

  my $exporter_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Using export port = $exporter_port\n";
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'prometheus:20 prometheus.http:20 prometheus.http.clf:10',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_prometheus.c' => {
        PrometheusEngine => 'on',
        PrometheusLog => $setup->{log_file},
        PrometheusTables => $table_dir,
        PrometheusExporter => "127.0.0.1:$exporter_port",
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require LWP::UserAgent;

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow server to start up
      sleep(2);

      my $ua = LWP::UserAgent->new();
      $ua->timeout(3);

      my $url = "http://127.0.0.1:$exporter_port/";
      my $resp = $ua->get($url);

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# response: ", $resp->status_line, "\n";
      }

      my $expected = 200;
      my $resp_code = $resp->code;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'OK';
      my $resp_msg = $resp->message;
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      my $headers = $resp->headers;
      my $content_type = $headers->header('Content-Type');
      $expected = 'text/plain';
      $self->assert($expected eq $content_type,
        test_msg("Expected Content-Type '$expected', got '$content_type'"));
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub prom_scrape_metrics_uri {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $table_dir)) {
      die("Can't set perms on $table_dir to 0755: $!");
    }

    unless (chown($setup->{uid}, $setup->{gid}, $table_dir)) {
      die("Can't set owner of $table_dir to $setup->{uid}/$setup->{gid}: $!");
    }
  }

  my $exporter_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Using export port = $exporter_port\n";
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'prometheus:20 prometheus.db:20 prometheus.http:20 prometheus.http.clf:10 prometheus.metric:20 prometheus.metric.db:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_prometheus.c' => {
        PrometheusEngine => 'on',
        PrometheusLog => $setup->{log_file},
        PrometheusTables => $table_dir,
        PrometheusExporter => "127.0.0.1:$exporter_port",
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require LWP::UserAgent;

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow server to start up
      sleep(2);

      my $ua = LWP::UserAgent->new();
      $ua->timeout(3);

      my $url = "http://127.0.0.1:$exporter_port/metrics";
      my $resp = $ua->get($url);

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# response: ", $resp->status_line, "\n";
        print STDERR "#   ", $resp->content, "\n";
      }

      my $expected = 200;
      my $resp_code = $resp->code;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'OK';
      my $resp_msg = $resp->message;
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      my $headers = $resp->headers;
      my $content_type = $headers->header('Content-Type');
      $expected = 'text/plain';
      $self->assert($expected eq $content_type,
        test_msg("Expected Content-Type '$expected', got '$content_type'"));
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub prom_scrape_metric_build_info {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $table_dir)) {
      die("Can't set perms on $table_dir to 0755: $!");
    }

    unless (chown($setup->{uid}, $setup->{gid}, $table_dir)) {
      die("Can't set owner of $table_dir to $setup->{uid}/$setup->{gid}: $!");
    }
  }

  my $exporter_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Using export port = $exporter_port\n";
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'prometheus:20 prometheus.db:20 prometheus.http:20 prometheus.http.clf:10 prometheus.metric:20 prometheus.metric.db:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_prometheus.c' => {
        PrometheusEngine => 'on',
        PrometheusLog => $setup->{log_file},
        PrometheusTables => $table_dir,
        PrometheusExporter => "127.0.0.1:$exporter_port",
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require LWP::UserAgent;

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow server to start up
      sleep(2);

      my $ua = LWP::UserAgent->new();
      $ua->timeout(3);

      my $url = "http://127.0.0.1:$exporter_port/metrics";
      my $resp = $ua->get($url);

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# response: ", $resp->status_line, "\n";
        print STDERR "#   ", $resp->content, "\n";
      }

      my $expected = 200;
      my $resp_code = $resp->code;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'OK';
      my $resp_msg = $resp->message;
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      my $headers = $resp->headers;
      my $content_type = $headers->header('Content-Type');
      $expected = 'text/plain';
      $self->assert($expected eq $content_type,
        test_msg("Expected Content-Type '$expected', got '$content_type'"));

      my $content = $resp->content;
      my $lines = [split(/\n/, $content)];

      $expected = '^# HELP proftpd_build_info .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_build_info counter$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_build_info{mod_prometheus_version="\S+",proftpd_version="\S+"} 1$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub prom_scrape_metric_startup_time {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $table_dir)) {
      die("Can't set perms on $table_dir to 0755: $!");
    }

    unless (chown($setup->{uid}, $setup->{gid}, $table_dir)) {
      die("Can't set owner of $table_dir to $setup->{uid}/$setup->{gid}: $!");
    }
  }

  my $exporter_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Using export port = $exporter_port\n";
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'prometheus:20 prometheus.db:20 prometheus.http:20 prometheus.http.clf:10 prometheus.metric:20 prometheus.metric.db:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_prometheus.c' => {
        PrometheusEngine => 'on',
        PrometheusLog => $setup->{log_file},
        PrometheusTables => $table_dir,
        PrometheusExporter => "127.0.0.1:$exporter_port",
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require LWP::UserAgent;

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow server to start up
      sleep(2);

      my $ua = LWP::UserAgent->new();
      $ua->timeout(3);

      my $url = "http://127.0.0.1:$exporter_port/metrics";
      my $resp = $ua->get($url);

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# response: ", $resp->status_line, "\n";
        print STDERR "#   ", $resp->content, "\n";
      }

      my $expected = 200;
      my $resp_code = $resp->code;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'OK';
      my $resp_msg = $resp->message;
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      my $headers = $resp->headers;
      my $content_type = $headers->header('Content-Type');
      $expected = 'text/plain';
      $self->assert($expected eq $content_type,
        test_msg("Expected Content-Type '$expected', got '$content_type'"));

      my $content = $resp->content;
      my $lines = [split(/\n/, $content)];

      $expected = '^# HELP proftpd_startup_time .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_startup_time counter$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_startup_time \d+$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub prom_scrape_metric_connection {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $table_dir)) {
      die("Can't set perms on $table_dir to 0755: $!");
    }

    unless (chown($setup->{uid}, $setup->{gid}, $table_dir)) {
      die("Can't set owner of $table_dir to $setup->{uid}/$setup->{gid}: $!");
    }
  }

  my $exporter_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Using export port = $exporter_port\n";
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'prometheus:20 prometheus.db:20 prometheus.http:20 prometheus.http.clf:10 prometheus.metric:30 prometheus.metric.db:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_prometheus.c' => {
        PrometheusEngine => 'on',
        PrometheusLog => $setup->{log_file},
        PrometheusTables => $table_dir,
        PrometheusExporter => "127.0.0.1:$exporter_port",
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require LWP::UserAgent;

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow server to start up
      sleep(2);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});
      $client->quit();

      my $ua = LWP::UserAgent->new();
      $ua->timeout(3);

      my $url = "http://127.0.0.1:$exporter_port/metrics";
      my $resp = $ua->get($url);

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# response: ", $resp->status_line, "\n";
        print STDERR "#   ", $resp->content, "\n";
      }

      my $expected = 200;
      my $resp_code = $resp->code;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'OK';
      my $resp_msg = $resp->message;
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      my $headers = $resp->headers;
      my $content_type = $headers->header('Content-Type');
      $expected = 'text/plain';
      $self->assert($expected eq $content_type,
        test_msg("Expected Content-Type '$expected', got '$content_type'"));

      my $content = $resp->content;
      my $lines = [split(/\n/, $content)];

      # Counter

      $expected = '^# HELP proftpd_connection_total .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_connection_total counter$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_connection_total{protocol="ftp"} 1$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      # Gauge

      $expected = '^# HELP proftpd_connection_count .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_connection_count gauge$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_connection_count{protocol="ftp"} 0$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub prom_scrape_metric_connection_refused {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $table_dir)) {
      die("Can't set perms on $table_dir to 0755: $!");
    }

    unless (chown($setup->{uid}, $setup->{gid}, $table_dir)) {
      die("Can't set owner of $table_dir to $setup->{uid}/$setup->{gid}: $!");
    }
  }

  my $exporter_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Using export port = $exporter_port\n";
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'prometheus:20 prometheus.db:20 prometheus.http:20 prometheus.http.clf:10 prometheus.metric:20 prometheus.metric.db:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_prometheus.c' => {
        PrometheusEngine => 'on',
        PrometheusLog => $setup->{log_file},
        PrometheusTables => $table_dir,
        PrometheusExporter => "127.0.0.1:$exporter_port",
      },
    },

    Limit => {
      LOGIN => {
        DenyAll => '',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require LWP::UserAgent;

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow server to start up
      sleep(2);

      eval { ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 1, 1) };
      unless ($@) {
        die("Connection succeeded unexpectedly");
      }

      my $ua = LWP::UserAgent->new();
      $ua->timeout(3);

      my $url = "http://127.0.0.1:$exporter_port/metrics";
      my $resp = $ua->get($url);

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# response: ", $resp->status_line, "\n";
        print STDERR "#   ", $resp->content, "\n";
      }

      my $expected = 200;
      my $resp_code = $resp->code;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'OK';
      my $resp_msg = $resp->message;
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      my $headers = $resp->headers;
      my $content_type = $headers->header('Content-Type');
      $expected = 'text/plain';
      $self->assert($expected eq $content_type,
        test_msg("Expected Content-Type '$expected', got '$content_type'"));

      my $content = $resp->content;
      my $lines = [split(/\n/, $content)];

      $expected = '^# HELP proftpd_connection_refused_total .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_connection_refused_total counter$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_connection_refused_total{protocol="ftp"} 1$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub prom_scrape_metric_log_message {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $table_dir)) {
      die("Can't set perms on $table_dir to 0755: $!");
    }

    unless (chown($setup->{uid}, $setup->{gid}, $table_dir)) {
      die("Can't set owner of $table_dir to $setup->{uid}/$setup->{gid}: $!");
    }
  }

  my $exporter_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Using export port = $exporter_port\n";
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'event:20 prometheus:20 prometheus.db:20 prometheus.http:20 prometheus.http.clf:10 prometheus.metric:20 prometheus.metric.db:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_prometheus.c' => {
        PrometheusEngine => 'on',
        PrometheusLog => $setup->{log_file},
        PrometheusTables => $table_dir,
        PrometheusExporter => "127.0.0.1:$exporter_port",
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require LWP::UserAgent;

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow server to start up
      sleep(2);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});
      $client->quit();

      my $ua = LWP::UserAgent->new();
      $ua->timeout(3);

      my $url = "http://127.0.0.1:$exporter_port/metrics";
      my $resp = $ua->get($url);

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# response: ", $resp->status_line, "\n";
        print STDERR "#   ", $resp->content, "\n";
      }

      my $expected = 200;
      my $resp_code = $resp->code;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'OK';
      my $resp_msg = $resp->message;
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      my $headers = $resp->headers;
      my $content_type = $headers->header('Content-Type');
      $expected = 'text/plain';
      $self->assert($expected eq $content_type,
        test_msg("Expected Content-Type '$expected', got '$content_type'"));

      my $content = $resp->content;
      my $lines = [split(/\n/, $content)];

      $expected = '^# HELP proftpd_log_message_total .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_log_message_total counter$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_log_message_total{level="debug",protocol="ftp"} \d+$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_log_message_total{level="error",protocol="ftp"} \d+$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_log_message_total{level="info",protocol="ftp"} \d+$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub prom_scrape_metric_auth_ok {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $table_dir)) {
      die("Can't set perms on $table_dir to 0755: $!");
    }

    unless (chown($setup->{uid}, $setup->{gid}, $table_dir)) {
      die("Can't set owner of $table_dir to $setup->{uid}/$setup->{gid}: $!");
    }
  }

  my $exporter_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Using export port = $exporter_port\n";
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'auth:20 prometheus:20 prometheus.db:20 prometheus.http:20 prometheus.http.clf:10 prometheus.metric:20 prometheus.metric.db:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_prometheus.c' => {
        PrometheusEngine => 'on',
        PrometheusLog => $setup->{log_file},
        PrometheusTables => $table_dir,
        PrometheusExporter => "127.0.0.1:$exporter_port",
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require LWP::UserAgent;

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow server to start up
      sleep(2);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});
      $client->quit();

      my $ua = LWP::UserAgent->new();
      $ua->timeout(3);

      my $url = "http://127.0.0.1:$exporter_port/metrics";
      my $resp = $ua->get($url);

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# response: ", $resp->status_line, "\n";
        print STDERR "#   ", $resp->content, "\n";
      }

      my $expected = 200;
      my $resp_code = $resp->code;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'OK';
      my $resp_msg = $resp->message;
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      my $headers = $resp->headers;
      my $content_type = $headers->header('Content-Type');
      $expected = 'text/plain';
      $self->assert($expected eq $content_type,
        test_msg("Expected Content-Type '$expected', got '$content_type'"));

      my $content = $resp->content;
      my $lines = [split(/\n/, $content)];

      $expected = '^# HELP proftpd_auth_total .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_auth_total counter$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_auth_total{method="password",protocol="ftp"} 1+$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub prom_scrape_metric_auth_anon_ok {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    mkpath($table_dir);

    unless (chmod(0755, $table_dir)) {
      die("Can't set perms on $table_dir to 0755: $!");
    }

    unless (chown($setup->{uid}, $setup->{gid}, $table_dir)) {
      die("Can't set owner of $table_dir to $setup->{uid}/$setup->{gid}: $!");
    }
  }

  my $exporter_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Using export port = $exporter_port\n";
  }

  my $anon_dir = File::Spec->rel2abs($tmpdir);
  my ($config_user, $config_group) = config_get_identity();

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'auth:20 prometheus:20 prometheus.db:20 prometheus.http:20 prometheus.http.clf:10 prometheus.metric:20 prometheus.metric.db:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_prometheus.c' => {
        PrometheusEngine => 'on',
        PrometheusLog => $setup->{log_file},
        PrometheusTables => $table_dir,
        PrometheusExporter => "127.0.0.1:$exporter_port",
      },
    },

    Anonymous => {
      $anon_dir => {
        User => $config_user,
        Group => $config_group,
        UserAlias => "anonymous $config_user",
        RequireValidShell => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require LWP::UserAgent;

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow server to start up
      sleep(2);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login('anonymous', 'nospam@ftp.org');
      $client->quit();

      my $ua = LWP::UserAgent->new();
      $ua->timeout(3);

      my $url = "http://127.0.0.1:$exporter_port/metrics";
      my $resp = $ua->get($url);

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# response: ", $resp->status_line, "\n";
        print STDERR "#   ", $resp->content, "\n";
      }

      my $expected = 200;
      my $resp_code = $resp->code;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'OK';
      my $resp_msg = $resp->message;
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      my $headers = $resp->headers;
      my $content_type = $headers->header('Content-Type');
      $expected = 'text/plain';
      $self->assert($expected eq $content_type,
        test_msg("Expected Content-Type '$expected', got '$content_type'"));

      my $content = $resp->content;
      my $lines = [split(/\n/, $content)];

      $expected = '^# HELP proftpd_auth_total .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_auth_total counter$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_auth_total{method="anonymous",protocol="ftp"} 1+$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub prom_config_exporter_addr {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $table_dir)) {
      die("Can't set perms on $table_dir to 0755: $!");
    }

    unless (chown($setup->{uid}, $setup->{gid}, $table_dir)) {
      die("Can't set owner of $table_dir to $setup->{uid}/$setup->{gid}: $!");
    }
  }

  my $exporter_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Using export port = $exporter_port\n";
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'prometheus:20 prometheus.http:20 prometheus.http.clf:10',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_prometheus.c' => {
        PrometheusEngine => 'on',
        PrometheusLog => $setup->{log_file},
        PrometheusTables => $table_dir,
        PrometheusExporter => "0.0.0.0:$exporter_port",
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require LWP::UserAgent;

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Allow server to start up
      sleep(2);

      my $ua = LWP::UserAgent->new();
      $ua->timeout(3);

      my $url = "http://127.0.0.1:$exporter_port/metrics";
      my $resp = $ua->get($url);

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# response: ", $resp->status_line, "\n";
      }

      my $expected = 200;
      my $resp_code = $resp->code;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'OK';
      my $resp_msg = $resp->message;
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      my $headers = $resp->headers;
      my $content_type = $headers->header('Content-Type');
      $expected = 'text/plain';
      $self->assert($expected eq $content_type,
        test_msg("Expected Content-Type '$expected', got '$content_type'"));
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

1;
