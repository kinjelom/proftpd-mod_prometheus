package ProFTPD::Tests::Modules::mod_prometheus::sftp;

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
  prom_scrape_metric_handshake_error_ssh2 => {
    order => ++$order,
    test_class => [qw(forking mod_sftp prometheus)],
  },

  prom_scrape_metric_sftp_protocol => {
    order => ++$order,
    test_class => [qw(forking mod_sftp prometheus)],
  },

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  # Check for the required Perl modules:
  #
  #  LWP-UserAgent
  #  Net-SSH2
  #  Net-SSH2-SFTP

  my $required = [qw(
    LWP::UserAgent
    Net::SSH2
    Net::SSH2::SFTP
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

sub set_up {
  my $self = shift;
  $self->SUPER::set_up(@_);

  # Make sure that mod_sftp does not complain about permissions on the hostkey
  # files.

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_sftp/ssh_host_rsa_key");
  my $dsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_sftp/ssh_host_dsa_key");

  unless (chmod(0400, $rsa_host_key, $dsa_host_key)) {
    die("Can't set perms on $rsa_host_key, $dsa_host_key: $!");
  }
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

sub prom_scrape_metric_handshake_error_ssh2 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");
  my $exporter_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_sftp/ssh_host_rsa_key");
  my $dsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_sftp/ssh_host_dsa_key");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'prometheus:20 prometheus.http:20 sftp:20',

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

      'mod_sftp.c' => [
        "SFTPEngine on",
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPHostKey $dsa_host_key",
      ],
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

  require Net::SSH2;
  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $ssh2 = Net::SSH2->new();

      my $cipher = 'arcfour';
      $ssh2->method('crypt_cs', $cipher);

      sleep(2);

      if ($ssh2->connect('127.0.0.1', $port)) {
        die("Connected to SSH server unexpectedly");
      }

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

      $expected = '^# HELP proftpd_handshake_error_total .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_handshake_error_total counter$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_handshake_error_total\{protocol="ssh2"\} 1+$';
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

sub prom_scrape_metric_sftp_protocol {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'prometheus');

  my $table_dir = File::Spec->rel2abs("$tmpdir/var/prometheus");
  my $exporter_port = ProFTPD::TestSuite::Utils::get_high_numbered_port();

  my $rsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_sftp/ssh_host_rsa_key");
  my $dsa_host_key = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_sftp/ssh_host_dsa_key");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'prometheus:20 prometheus.http:20 sftp:20',

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

      'mod_sftp.c' => [
        "SFTPEngine on",
        "SFTPLog $setup->{log_file}",
        "SFTPHostKey $rsa_host_key",
        "SFTPHostKey $dsa_host_key",
      ],
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

  require Net::SSH2;
  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $ssh2 = Net::SSH2->new();

      sleep(2);

      unless ($ssh2->connect('127.0.0.1', $port)) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't connect to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      unless ($ssh2->auth_password($setup->{user}, $setup->{passwd})) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't login to SSH2 server: [$err_name] ($err_code) $err_str");
      }

      my $sftp = $ssh2->sftp();
      unless ($sftp) {
        my ($err_code, $err_name, $err_str) = $ssh2->error();
        die("Can't use SFTP on SSH2 server: [$err_name] ($err_code) $err_str");
      }

      $sftp = undef;

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

      $expected = '^# HELP proftpd_sftp_protocol_total .*?\.$';
      my $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^# TYPE proftpd_sftp_protocol_total counter$';
      $seen = saw_expected_content($lines, $expected);
      $self->assert($seen,
        test_msg("Did not see '$expected' in '$content' as expected"));

      $expected = '^proftpd_sftp_protocol_total\{protocol="sftp",version="3"\} 1+$';
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
