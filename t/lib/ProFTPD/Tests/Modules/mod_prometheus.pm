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

  prom_scrape_metrics_uri_with_gzip => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_metrics_uri_with_basic_auth_success => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_metrics_uri_with_basic_auth_missing_credentials => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_metrics_uri_with_basic_auth_wrong_username => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_metrics_uri_with_basic_auth_wrong_password => {
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

  prom_scrape_metric_auth_error_unknown_user => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_metric_auth_error_bad_password => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_metric_auth_error_incomplete => {
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

  prom_scrape_metric_login_succeeded => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_metric_login_multiple_times => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_metric_login_user_quit => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_metric_login_user_multiple_times => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_metric_login_pass_multiple_times => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_metric_login_in_progress => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_metric_login_error_bad_user => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_metric_login_error_bad_password => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_metric_login_error_user_bad_pass_good_pass => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_metric_login_error_pass_multiple_times => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_metric_login_error_denied_acl => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_metric_timeout_idle => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_metric_timeout_login => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_metric_timeout_notransfer => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_metric_timeout_session => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
  },

  prom_scrape_metric_timeout_stalled => {
    order => ++$order,
    test_class => [qw(forking prometheus)],
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

  return testsuite_get_runnable_tests($TESTS);
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
  my $exporter_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'prometheus:20 prometheus.http:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

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
    AuthOrder => 'mod_auth_file.c',

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
    AuthOrder => 'mod_auth_file.c',

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
    AuthOrder => 'mod_auth_file.c',

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
    AuthOrder => 'mod_auth_file.c',

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

sub prom_scrape_metrics_uri_with_gzip {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

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
    AuthOrder => 'mod_auth_file.c',

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
      $ua->default_header('Accept-Encoding' => 'deflate,gzip,foobar');

      my $url = "http://127.0.0.1:$exporter_port/metrics";
      my $resp = $ua->get($url);

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# response: ", $resp->status_line, "\n";
        print STDERR "#   ", $resp->decoded_content, "\n";
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

      my $content_encoding = $headers->header('Content-Encoding');
      $expected = 'gzip';
      $self->assert($expected eq $content_encoding,
        test_msg("Expected Content-Encoding '$expected', got '$content_encoding'"));

      my $content = $resp->decoded_content;
      my $lines = [split(/\n/, $content)];

      $expected = '^# HELP proftpd_build_info .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
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

sub prom_scrape_metrics_uri_with_basic_auth_success {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

  my $exporter_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Using export port = $exporter_port\n";
  }

  my $exporter_realm = 'proftpd';
  my $exporter_username = 'prometheus';
  my $exporter_password = 'Pr0m3th3u$';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'prometheus:20 prometheus.db:20 prometheus.http:20 prometheus.http.clf:10 prometheus.metric:20 prometheus.metric.db:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_prometheus.c' => {
        PrometheusEngine => 'on',
        PrometheusLog => $setup->{log_file},
        PrometheusTables => $table_dir,
        PrometheusExporter => "127.0.0.1:$exporter_port $exporter_username $exporter_password",
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
      $ua->credentials("127.0.0.1:$exporter_port", $exporter_realm,
        $exporter_username, $exporter_password);

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

sub prom_scrape_metrics_uri_with_basic_auth_from_env {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

  my $exporter_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Using export port = $exporter_port\n";
  }

  my $exporter_realm = 'proftpd';
  my $exporter_username = 'prometheus';
  my $exporter_password = 'Pr0m3th3u$';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'prometheus:20 prometheus.db:20 prometheus.http:20 prometheus.http.clf:10 prometheus.metric:20 prometheus.metric.db:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

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

  $ENV{PROMETHEUS_USERNAME} = $exporter_username;
  $ENV{PROMETHEUS_PASSWORD} = $exporter_password;

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
      $ua->credentials("127.0.0.1:$exporter_port", $exporter_realm,
        $exporter_username, $exporter_password);

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

sub prom_scrape_metrics_uri_with_basic_auth_missing_credentials {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

  my $exporter_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Using export port = $exporter_port\n";
  }

  my $exporter_realm = 'proftpd';
  my $exporter_username = 'prometheus';
  my $exporter_password = 'Pr0m3th3u$';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'prometheus:20 prometheus.db:20 prometheus.http:20 prometheus.http.clf:10 prometheus.metric:20 prometheus.metric.db:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_prometheus.c' => {
        PrometheusEngine => 'on',
        PrometheusLog => $setup->{log_file},
        PrometheusTables => $table_dir,
        PrometheusExporter => "127.0.0.1:$exporter_port $exporter_username $exporter_password",
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

      my $expected = 401;
      my $resp_code = $resp->code;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'Unauthorized';
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

sub prom_scrape_metrics_uri_with_basic_auth_wrong_username {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

  my $exporter_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Using export port = $exporter_port\n";
  }

  my $exporter_realm = 'proftpd';
  my $exporter_username = 'prometheus';
  my $exporter_password = 'Pr0m3th3u$';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'prometheus:20 prometheus.db:20 prometheus.http:20 prometheus.http.clf:10 prometheus.metric:20 prometheus.metric.db:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_prometheus.c' => {
        PrometheusEngine => 'on',
        PrometheusLog => $setup->{log_file},
        PrometheusTables => $table_dir,
        PrometheusExporter => "127.0.0.1:$exporter_port $exporter_username $exporter_password",
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
      $ua->credentials("127.0.0.1:$exporter_port", $exporter_realm, 'foo',
        'bar');

      my $url = "http://127.0.0.1:$exporter_port/metrics";
      my $resp = $ua->get($url);

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# response: ", $resp->status_line, "\n";
        print STDERR "#   ", $resp->content, "\n";
      }

      my $expected = 401;
      my $resp_code = $resp->code;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'Unauthorized';
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

sub prom_scrape_metrics_uri_with_basic_auth_wrong_password {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

  my $exporter_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Using export port = $exporter_port\n";
  }

  my $exporter_realm = 'proftpd';
  my $exporter_username = 'prometheus';
  my $exporter_password = 'Pr0m3th3u$';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'prometheus:20 prometheus.db:20 prometheus.http:20 prometheus.http.clf:10 prometheus.metric:20 prometheus.metric.db:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_prometheus.c' => {
        PrometheusEngine => 'on',
        PrometheusLog => $setup->{log_file},
        PrometheusTables => $table_dir,
        PrometheusExporter => "127.0.0.1:$exporter_port $exporter_username $exporter_password",
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
      $ua->credentials("127.0.0.1:$exporter_port", $exporter_realm,
        $exporter_username, 'bar');

      my $url = "http://127.0.0.1:$exporter_port/metrics";
      my $resp = $ua->get($url);

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# response: ", $resp->status_line, "\n";
        print STDERR "#   ", $resp->content, "\n";
      }

      my $expected = 401;
      my $resp_code = $resp->code;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'Unauthorized';
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
    AuthOrder => 'mod_auth_file.c',

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

      $expected = '^proftpd_build_info\{mod_prometheus_version="\S+",proftpd_version="\S+"\} 1$';
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
    AuthOrder => 'mod_auth_file.c',

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
    AuthOrder => 'mod_auth_file.c',

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
      sleep(2);
      $client->quit();
      sleep(1);

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

      $expected = '^proftpd_connection_total\{protocol="ftp"\} 1$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      # Gauge

      $expected = '^# HELP proftpd_connection_count .*?\.$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_connection_count gauge$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      # Race: sometimes the session has not yet finished.
      $expected = '^proftpd_connection_count\{protocol="ftp"\} (0|1)$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      # Histogram

      $expected = '^# HELP proftpd_connection_duration_seconds .*?\.$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_connection_duration_seconds histogram$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_connection_duration_seconds_bucket\{le="\+Inf",protocol="ftp"\} \d+$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_connection_duration_seconds_count\{protocol="ftp"\} 1$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_connection_duration_seconds_sum\{protocol="ftp"\} \d+$';
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
    AuthOrder => 'mod_auth_file.c',

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

      $expected = '^proftpd_connection_refused_total\{protocol="ftp"\} \d+$';
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
    AuthOrder => 'mod_auth_file.c',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_prometheus.c' => {
        PrometheusEngine => 'on',
        PrometheusLog => $setup->{log_file},
        PrometheusTables => $table_dir,
        PrometheusExporter => "127.0.0.1:$exporter_port",
        PrometheusOptions => 'EnableLogMessageMetrics',
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

      $expected = '^proftpd_log_message_total\{level="debug",protocol="ftp"\} \d+$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_log_message_total\{level="debug",protocol="ftp"\} \d+$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_log_message_total\{level="info",protocol="ftp"\} \d+$';
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
    AuthOrder => 'mod_auth_file.c',

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

      $expected = '^proftpd_auth_total\{method="password",protocol="ftp"\} 1+$';
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
    AuthOrder => 'mod_auth_file.c',

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

  my $port;
  ($port, $config_user, $config_group) = config_write($setup->{config_file},
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

      $expected = '^proftpd_auth_total\{method="anonymous",protocol="ftp"\} 1+$';
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

sub prom_scrape_metric_auth_error_unknown_user {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

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
    AuthOrder => 'mod_auth_file.c',

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
      eval { $client->login('foo', 'bar') };
      unless ($@) {
        die("Login succeeded unexpectedly");
      }
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

      my $content = $resp->content;
      my $lines = [split(/\n/, $content)];

      $expected = '^# HELP proftpd_auth_error_total .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_auth_error_total counter$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_auth_error_total\{protocol="ftp",reason="unknown user"\} 1+$';
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

sub prom_scrape_metric_auth_error_bad_password {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

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
    AuthOrder => 'mod_auth_file.c',

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
      eval { $client->login($setup->{user}, 'bar') };
      unless ($@) {
        die("Login succeeded unexpectedly");
      }
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

      my $content = $resp->content;
      my $lines = [split(/\n/, $content)];

      $expected = '^# HELP proftpd_auth_error_total .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_auth_error_total counter$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_auth_error_total\{protocol="ftp",reason="bad password"\} 1+$';
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

sub prom_scrape_metric_auth_error_incomplete {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

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
    AuthOrder => 'mod_auth_file.c',

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
      $client->user('foo');
      $client->quit();

      # Allow time for the session to end before scraping.
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

      my $content = $resp->content;
      my $lines = [split(/\n/, $content)];

      $expected = '^# HELP proftpd_auth_error_total .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_auth_error_total counter$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_auth_error_total\{protocol="ftp",reason="incomplete"\} 1+$';
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

sub prom_scrape_metric_directory_list {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

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
    AuthOrder => 'mod_auth_file.c',

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

      # LIST
      my $conn = $client->list_raw();
      unless ($conn) {
        die("LIST failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf;
      $conn->read($buf, 8192, 30);
      eval { $conn->close() };

      # NLST
      $buf = '';
      $conn = $client->nlst_raw();
      unless ($conn) {
        die("NLST failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      $conn->read($buf, 8192, 30);
      eval { $conn->close() };

      # MLSD
      $buf = '';
      $conn = $client->mlsd_raw();
      unless ($conn) {
        die("MLSD failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      $conn->read($buf, 8192, 30);
      eval { $conn->close() };

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

      my $content = $resp->content;
      my $lines = [split(/\n/, $content)];

      # Counter
      $expected = '^# HELP proftpd_directory_list_total .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_directory_list_total counter$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_directory_list_total\{protocol="ftp"\} 3+$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      # Gauge
      $expected = '^# HELP proftpd_directory_list_count .*?\.$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_directory_list_count gauge$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_directory_list_count\{protocol="ftp"\} 0+$';
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

sub prom_scrape_metric_directory_list_error {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

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
    AuthOrder => 'mod_auth_file.c',

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

      # LIST always succeeds, unfortunately.

      # NLST
      my $conn = $client->nlst_raw('/quxx/quzz');
      if ($conn) {
        die("NLST succeeded unexpectedly");
      }

      # MLSD
      $conn = $client->mlsd_raw('/alef/bet/vet');
      if ($conn) {
        die("MLSD succeeded unexpectedly");
      }

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

      my $content = $resp->content;
      my $lines = [split(/\n/, $content)];

      # Counter
      $expected = '^# HELP proftpd_directory_list_error_total .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_directory_list_error_total counter$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_directory_list_error_total\{protocol="ftp"\} 2+$';
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

sub prom_scrape_metric_file_download {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

  my $exporter_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Using export port = $exporter_port\n";
  }

  my $test_file = File::Spec->rel2abs("$tmpdir/test.dat");
  if (open(my $fh, "> $test_file")) {
    print $fh "AbCd" x 8192;
    unless (close($fh)) {
      die("Can't write $test_file: $!");
    }

  } else {
    die("Can't open $test_file: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'prometheus:20 prometheus.db:20 prometheus.http:20 prometheus.http.clf:10 prometheus.metric:20 prometheus.metric.db:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

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

      my ($resp_code, $resp_msg) = $client->retr($test_file);
      $self->assert_transfer_ok($resp_code, $resp_msg);
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
      $resp_code = $resp->code;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'OK';
      $resp_msg = $resp->message;
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      my $content = $resp->content;
      my $lines = [split(/\n/, $content)];

      # Counter

      $expected = '^# HELP proftpd_file_download_total .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_file_download_total counter$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_file_download_total\{protocol="ftp"\} 1+$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      # Gauge

      $expected = '^# HELP proftpd_file_download_count .*?\.$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_file_download_count gauge$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_file_download_count\{protocol="ftp"\} 0+$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      # Histogram

      $expected = '^# HELP proftpd_file_download_bytes .*?\.$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_file_download_bytes histogram$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_file_download_bytes_bucket\{le="\+Inf",protocol="ftp"\} 1+$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_file_download_bytes_count\{protocol="ftp"\} 1+$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_file_download_bytes_sum\{protocol="ftp"\} 32768+$';
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

sub prom_scrape_metric_file_download_error {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

  my $exporter_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Using export port = $exporter_port\n";
  }

  my $test_file = File::Spec->rel2abs("$tmpdir/test.dat");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'prometheus:20 prometheus.db:20 prometheus.http:20 prometheus.http.clf:10 prometheus.metric:20 prometheus.metric.db:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

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
      eval { $client->retr($test_file) };
      unless ($@) {
        die("RETR $test_file succeeded unexpectedly");
      }
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

      my $content = $resp->content;
      my $lines = [split(/\n/, $content)];

      # Counter
      $expected = '^# HELP proftpd_file_download_error_total .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_file_download_error_total counter$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_file_download_error_total\{protocol="ftp"\} 1+$';
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

sub prom_scrape_metric_file_upload {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

  my $exporter_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Using export port = $exporter_port\n";
  }

  my $test_file = File::Spec->rel2abs("$tmpdir/test.dat");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'prometheus:20 prometheus.db:20 prometheus.http:20 prometheus.http.clf:10 prometheus.metric:20 prometheus.metric.db:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

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

      my $conn = $client->stor_raw($test_file);
      unless ($conn) {
        die("Failed to STOR: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf = "Hello World!\n";
      $conn->write($buf, length($buf), 25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);
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
      $resp_code = $resp->code;
      $self->assert($expected == $resp_code,
        test_msg("Expected response code $expected, got $resp_code"));

      $expected = 'OK';
      $resp_msg = $resp->message;
      $self->assert($expected eq $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      my $content = $resp->content;
      my $lines = [split(/\n/, $content)];

      # Counter

      $expected = '^# HELP proftpd_file_upload_total .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_file_upload_total counter$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_file_upload_total\{protocol="ftp"\} 1+$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      # Gauge

      $expected = '^# HELP proftpd_file_upload_count .*?\.$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_file_upload_count gauge$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_file_upload_count\{protocol="ftp"\} 0+$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      # Histogram

      $expected = '^# HELP proftpd_file_upload_bytes .*?\.$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_file_upload_bytes histogram$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_file_upload_bytes_bucket\{le="\+Inf",protocol="ftp"\} 1+$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_file_upload_bytes_count\{protocol="ftp"\} 1+$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_file_upload_bytes_sum\{protocol="ftp"\} 13+$';
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

sub prom_scrape_metric_file_upload_error {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

  my $exporter_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Using export port = $exporter_port\n";
  }

  my $test_file = File::Spec->rel2abs("$tmpdir/sub.d/test.dat");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'prometheus:20 prometheus.db:20 prometheus.http:20 prometheus.http.clf:10 prometheus.metric:20 prometheus.metric.db:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

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

      my $conn = $client->stor_raw($test_file);
      if ($conn) {
        die("STOR $test_file succeeded unexpectedly");
      }
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

      my $content = $resp->content;
      my $lines = [split(/\n/, $content)];

      # Counter
      $expected = '^# HELP proftpd_file_upload_error_total .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_file_upload_error_total counter$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_file_upload_error_total\{protocol="ftp"\} 1+$';
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

sub prom_scrape_metric_login_succeeded {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

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
    AuthOrder => 'mod_auth_file.c',

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
      sleep(3);

      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($setup->{user}, $setup->{passwd});
      $client->quit();

      sleep(1);

      my $ua = LWP::UserAgent->new();
      $ua->timeout(5);

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

      my $content = $resp->content;
      my $lines = [split(/\n/, $content)];

      # Counter

      $expected = '^# HELP proftpd_login_total .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_login_total counter$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_login_total\{protocol="ftp"\} 1+$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      # Gauge

      $expected = '^# HELP proftpd_login_count .*?\.$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_login_count gauge$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_login_count\{protocol="ftp"\} 0+$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      # Histogram

      $expected = '^# HELP proftpd_login_delay_seconds .*?\.$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_login_delay_seconds histogram$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_login_delay_seconds_bucket\{le="\+Inf",protocol="ftp"\} 1$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_login_delay_seconds_count\{protocol="ftp"\} 1$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_login_delay_seconds_sum\{protocol="ftp"\} \d+$';
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

sub prom_scrape_metric_login_multiple_times {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

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
    AuthOrder => 'mod_auth_file.c',

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
      eval { $client->login($setup->{user}, $setup->{passwd}) };
      eval { $client->login($setup->{user}, $setup->{passwd}) };
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

      my $content = $resp->content;
      my $lines = [split(/\n/, $content)];

      # Counter
      $expected = '^# HELP proftpd_login_total .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_login_total counter$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_login_total\{protocol="ftp"\} 1+$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      # Gauge
      $expected = '^# HELP proftpd_login_count .*?\.$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_login_count gauge$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_login_count\{protocol="ftp"\} 0+$';
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

sub prom_scrape_metric_login_user_quit {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

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
    AuthOrder => 'mod_auth_file.c',

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
      $client->user($setup->{user});
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

      my $content = $resp->content;
      my $lines = [split(/\n/, $content)];

      # Counter
      $expected = '^# HELP proftpd_login_total .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_login_total counter$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_login_total 0+$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      # Gauge
      $expected = '^# HELP proftpd_login_count .*?\.$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_login_count gauge$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      # Race: sometimes the session has not yet finished.
      $expected = '^proftpd_login_count\{protocol="ftp"\} (0|1)$';
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

sub prom_scrape_metric_login_user_multiple_times {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

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
    AuthOrder => 'mod_auth_file.c',

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
      $client->user($setup->{user});
      eval { $client->user($setup->{user}) };
      eval { $client->user($setup->{user}) };
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

      my $content = $resp->content;
      my $lines = [split(/\n/, $content)];

      # Counter
      $expected = '^# HELP proftpd_login_total .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_login_total counter$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_login_total 0+$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      # Gauge
      $expected = '^# HELP proftpd_login_count .*?\.$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_login_count gauge$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_login_count\{protocol="ftp"\} 0+$';
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

sub prom_scrape_metric_login_pass_multiple_times {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

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
    AuthOrder => 'mod_auth_file.c',

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
      eval { $client->pass('foo') };
      eval { $client->pass('foo') };
      eval { $client->pass('foo') };
      $client->user($setup->{user});
      eval { $client->pass('foo') };
      eval { $client->pass('foo') };
      $client->user($setup->{user});
      $client->pass($setup->{passwd});
      eval { $client->pass('foo') };
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

      my $content = $resp->content;
      my $lines = [split(/\n/, $content)];

      # Counter
      $expected = '^# HELP proftpd_login_total .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_login_total counter$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_login_total\{protocol="ftp"\} 1+$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      # Gauge
      $expected = '^# HELP proftpd_login_count .*?\.$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_login_count gauge$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_login_count\{protocol="ftp"\} 0+$';
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

sub prom_scrape_metric_login_in_progress {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

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
    AuthOrder => 'mod_auth_file.c',

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
      $client->user($setup->{user});

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

      my $content = $resp->content;
      my $lines = [split(/\n/, $content)];

      # Counter
      $expected = '^# HELP proftpd_login_total .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_login_total counter$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_login_total 0+$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      # Gauge
      $expected = '^# HELP proftpd_login_count .*?\.$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_login_count gauge$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_login_count\{protocol="ftp"\} 1+$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $client->quit();
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

sub prom_scrape_metric_login_error_bad_user {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

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
    AuthOrder => 'mod_auth_file.c',

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
      eval { $client->login('foo', 'bar') };
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

      my $content = $resp->content;
      my $lines = [split(/\n/, $content)];

      $expected = '^# HELP proftpd_login_error_total .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_login_error_total counter$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_login_error_total\{protocol="ftp"\} 1+$';
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

sub prom_scrape_metric_login_error_bad_password {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

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
    AuthOrder => 'mod_auth_file.c',

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
      eval { $client->login($setup->{user}, 'bar') };
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

      my $content = $resp->content;
      my $lines = [split(/\n/, $content)];

      $expected = '^# HELP proftpd_login_error_total .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_login_error_total counter$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_login_error_total\{protocol="ftp"\} 1+$';
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

sub prom_scrape_metric_login_error_user_bad_pass_good_pass {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

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
    AuthOrder => 'mod_auth_file.c',

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
      $client->user($setup->{user});
      eval { $client->pass('foo') };
      $client->user($setup->{user});
      $client->pass($setup->{passwd});
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

      my $content = $resp->content;
      my $lines = [split(/\n/, $content)];

      $expected = '^# HELP proftpd_login_error_total .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_login_error_total counter$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_login_error_total\{protocol="ftp"\} 1+$';
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

sub prom_scrape_metric_login_error_pass_multiple_times {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

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
    AuthOrder => 'mod_auth_file.c',

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
      eval { $client->pass('foo') };
      eval { $client->pass('foo') };
      eval { $client->pass('foo') };
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

      my $content = $resp->content;
      my $lines = [split(/\n/, $content)];

      $expected = '^# HELP proftpd_login_error_total .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_login_error_total counter$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_login_error_total\{protocol="ftp"\} 3+$';
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

sub prom_scrape_metric_login_error_denied_acl {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

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
    AuthOrder => 'mod_auth_file.c',

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
        DenyUser => $setup->{user},
      },
    }
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
      eval { $client->login($setup->{user}, $setup->{passwd}) };
      unless ($@) {
        die("Login succeeded unexpectedly");
      }
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

      my $content = $resp->content;
      my $lines = [split(/\n/, $content)];

      $expected = '^# HELP proftpd_login_error_total .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_login_error_total counter$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_login_error_total\{protocol="ftp"\} 1+$';
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

sub prom_scrape_metric_timeout_idle {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

  my $exporter_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Using export port = $exporter_port\n";
  }

  my $timeout_idle = 3;
  my $timeout_delay = $timeout_idle + 2;

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'prometheus:20 prometheus.db:20 prometheus.http:20 prometheus.http.clf:10 prometheus.metric:20 prometheus.metric.db:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    TimeoutIdle => $timeout_idle,

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
      $client->noop();

      # Wait for more than the TimeoutIdle period
      sleep($timeout_delay);

      eval { $client->noop() };
      unless ($@) {
        die("NOOP succeeded unexpectedly");
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

      my $content = $resp->content;
      my $lines = [split(/\n/, $content)];

      $expected = '^# HELP proftpd_timeout_total .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_timeout_total counter$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_timeout_total\{protocol="ftp",reason="TimeoutIdle"\} 1+$';
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

sub prom_scrape_metric_timeout_login {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

  my $exporter_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Using export port = $exporter_port\n";
  }

  my $timeout_login = 3;

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'prometheus:20 prometheus.db:20 prometheus.http:20 prometheus.http.clf:10 prometheus.metric:20 prometheus.metric.db:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    TimeoutLogin => $timeout_login,

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

      # Wait for 2s more than the TimeoutLogin period
      sleep($timeout_login + 2);

      eval { $client->user($setup->{user}) };
      unless ($@) {
        die("USER succeeded unexpectedly");
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

      my $content = $resp->content;
      my $lines = [split(/\n/, $content)];

      $expected = '^# HELP proftpd_timeout_total .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_timeout_total counter$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_timeout_total\{protocol="ftp",reason="TimeoutLogin"\} 1+$';
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

sub prom_scrape_metric_timeout_notransfer {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

  my $exporter_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Using export port = $exporter_port\n";
  }

  my $timeout_notransfer = 2;

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'prometheus:20 prometheus.db:20 prometheus.http:20 prometheus.http.clf:10 prometheus.metric:20 prometheus.metric.db:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    TimeoutNoTransfer => $timeout_notransfer,

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

      # Wait for 2s more than the TimeoutNoTransfer period
      for (my $i = 0; $i < $timeout_notransfer; $i++) {
        sleep(1);
        eval { $client->noop() };
      }

      sleep(2);

      eval { $client->noop() };
      unless ($@) {
        die("NOOP succeeded unexpectedly");
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

      my $content = $resp->content;
      my $lines = [split(/\n/, $content)];

      $expected = '^# HELP proftpd_timeout_total .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_timeout_total counter$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_timeout_total\{protocol="ftp",reason="TimeoutNoTransfer"\} 1+$';
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

sub prom_scrape_metric_timeout_session {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

  my $exporter_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Using export port = $exporter_port\n";
  }

  my $timeout_session = 3;

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'prometheus:20 prometheus.db:20 prometheus.http:20 prometheus.http.clf:10 prometheus.metric:20 prometheus.metric.db:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    TimeoutSession => $timeout_session,

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

      # Wait for 2s more than the TimeoutSession period
      for (my $i = 0; $i < $timeout_session; $i++) {
        sleep(1);
        eval { $client->noop() };
      }

      sleep(2);

      eval { $client->noop() };
      unless ($@) {
        die("NOOP succeeded unexpectedly");
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

      my $content = $resp->content;
      my $lines = [split(/\n/, $content)];

      $expected = '^# HELP proftpd_timeout_total .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_timeout_total counter$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_timeout_total\{protocol="ftp",reason="TimeoutSession"\} 1+$';
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

sub prom_scrape_metric_timeout_stalled {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");

  my $exporter_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Using export port = $exporter_port\n";
  }

  my $test_file = File::Spec->rel2abs("$tmpdir/test.dat");
  if (open(my $fh, "> $test_file")) {
    print $fh "AbCd" x 8192000;
    unless (close($fh)) {
      die("Can't write $test_file: $!");
    }

  } else {
    die("Can't open $test_file: $!");
  }

  my $timeout_stalled = 2;

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'prometheus:20 prometheus.db:20 prometheus.http:20 prometheus.http.clf:10 prometheus.metric:20 prometheus.metric.db:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    TimeoutStalled => $timeout_stalled,

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

      my $conn = $client->retr_raw($test_file);
      unless ($conn) {
        die("RETR failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      # Wait for 2s more than the stalled period
      sleep($timeout_stalled + 2);

      my $buf = '';
      $conn->read($buf, 8192, 30);
      eval { $conn->close() };

      eval { $client->noop() };
      unless ($@) {
        die("NOOP succeeded unexpectedly");
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

      my $content = $resp->content;
      my $lines = [split(/\n/, $content)];

      $expected = '^# HELP proftpd_timeout_total .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_timeout_total counter$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_timeout_total\{protocol="ftp",reason="TimeoutStalled"\} 1+$';
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
    AuthOrder => 'mod_auth_file.c',

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
