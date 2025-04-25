package ProFTPD::Tests::Modules::mod_prometheus::tls;

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
  prom_scrape_metric_handshake_error_tls_ctrl => {
    order => ++$order,
    test_class => [qw(forking mod_tls prometheus)],
  },

  prom_scrape_metric_handshake_error_tls_data => {
    order => ++$order,
    test_class => [qw(forking mod_tls prometheus)],
  },

  prom_scrape_metric_tls_protocol => {
    order => ++$order,
    test_class => [qw(forking mod_tls prometheus)],
  },

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  # Check for the required Perl modules:
  #
  #  LWP-UserAgent
  #  Net-FTPSSL

  my $required = [qw(
    LWP::UserAgent
    Net::FTPSSL
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

sub prom_scrape_metric_handshake_error_tls_ctrl {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");
  my $exporter_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();

  my $cert_file = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_tls/server-cert.pem");
  my $ca_file = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_tls/ca-cert.pem");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'prometheus:20 prometheus.db:30 prometheus.http:20 tls:20',

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

      'mod_tls.c' => {
        TLSEngine => 'on',
        TLSLog => $setup->{log_file},
        TLSRequired => 'on',
        TLSProtocol => 'TLSv1.2',
        TLSRSACertificateFile => $cert_file,
        TLSCACertificateFile => $ca_file,
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

  require Net::FTPSSL;
  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Give the server a chance to start up
      sleep(2);

      my $ssl_opts = {
        Encryption => 'E',
        Port => $port,
        SSL_version => 'TLSv1',
      };

      if ($ENV{TEST_VERBOSE}) {
        $ssl_opts->{Debug} = 1;
      }

      my $client = Net::FTPSSL->new('127.0.0.1', %$ssl_opts);
      if ($client) {
        die("TLS ctrl handshake succeeded unexpectedly");
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

      $expected = '^# HELP proftpd_handshake_error_total .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_handshake_error_total counter$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_handshake_error_total\{connection="ctrl",protocol="ftps"\} 1$';
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

sub prom_scrape_metric_handshake_error_tls_data {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");
  my $exporter_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();

  my $cert_file = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_tls/server-cert.pem");
  my $ca_file = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_tls/ca-cert.pem");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'event:20 prometheus:20 prometheus.db:30 prometheus.http:20 tls:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AuthOrder => 'mod_auth_file.c',

    TimeoutLinger => 1,

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

      'mod_tls.c' => {
        TLSEngine => 'on',
        TLSLog => $setup->{log_file},
        TLSRequired => 'on',
        TLSRSACertificateFile => $cert_file,
        TLSCACertificateFile => $ca_file,
        TLSOptions => 'EnableDiags NoSessionReuseRequired',
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

  require Net::FTPSSL;
  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Give the server a chance to start up
      sleep(2);

      my $ssl_opts = {
        Encryption => 'E',
        Port => $port,
        SSL_version => 'TLSv1.2',
      };

      if ($ENV{TEST_VERBOSE}) {
        $ssl_opts->{Debug} = 2;
      }

      my $client = Net::FTPSSL->new('127.0.0.1', %$ssl_opts);
      unless ($client) {
        die("Can't connect to FTPS server: " . IO::Socket::SSL::errstr());
      }

      my $data_opts = {
        SSL_cipher_list => 'MD5',

        # Explicitly disable reuse of the control session; necessary for
        # our other options to be honored.
        SSL_reuse_ctx => undef,
      };

      # Note: If we need to use different tricks here, depending on the
      # OpenSSL version used by Net::SSLeay (because of _e.g._ dropping of
      # SSLv3 support in OpenSSL 1.1.1x), we can use:
      #
      #  perl -mNet::SSLeay -e 'print Net::SSLeay::OpenSSL_version('OPENSSL_VERSION'), "\n";'
      #  OpenSSL 1.1.1  11 Sep 2018
      #
      # For now, we assume that the MD5 ciphersuites are sufficiently
      # disabled on a widespread enough basis to suffice for our needs.

      unless ($client->set_dc_from_hash($data_opts) == 2) {
        die("Can't set Net-FTPSSL data conn TLS cipher list");
      }

      unless ($client->login($setup->{user}, $setup->{passwd})) {
        die("Can't login: " . $client->last_message());
      }

      my $res = $client->list('.');
      if ($res) {
        die("LIST succeeded unexpectedly");
      }

      eval { $client->quit() };

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

      $expected = '^# HELP proftpd_handshake_error_total .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_handshake_error_total counter$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_handshake_error_total\{connection="data",protocol="ftps"\} 1$';
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

sub prom_scrape_metric_tls_protocol {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");
  my $exporter_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();

  my $cert_file = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_tls/server-cert.pem");
  my $ca_file = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_tls/ca-cert.pem");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'prometheus:20 prometheus.db:30 prometheus.http:20 tls:20',

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

      'mod_tls.c' => {
        TLSEngine => 'on',
        TLSLog => $setup->{log_file},
        TLSRequired => 'on',
        TLSRSACertificateFile => $cert_file,
        TLSCACertificateFile => $ca_file,
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

  require Net::FTPSSL;
  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Give the server a chance to start up
      sleep(2);

      my $ssl_opts = {
        Encryption => 'E',
        Port => $port,
      };

      if ($ENV{TEST_VERBOSE}) {
        $ssl_opts->{Debug} = 1;
      }

      my $client = Net::FTPSSL->new('127.0.0.1', %$ssl_opts);
      unless ($client) {
        die("Can't connect to FTPS server: " . IO::Socket::SSL::errstr());
      }

      unless ($client->login($setup->{user}, $setup->{passwd})) {
        die("Can't login: " . $client->last_message());
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

      $expected = '^# HELP proftpd_tls_protocol_total .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_tls_protocol_total counter$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_tls_protocol_total\{protocol="ftps",version="TLSv.*?"\} 1+$';
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

1;
