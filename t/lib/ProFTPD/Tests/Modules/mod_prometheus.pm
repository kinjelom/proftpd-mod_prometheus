package ProFTPD::Tests::Modules::mod_prometheus;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use Data::Dumper;
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
    prom_scrape_metrics_uri
  );
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
