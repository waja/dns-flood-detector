#!/usr/bin/perl

use strict;
use threads;
use threads::shared;
use Sys::Syslog;
use Data::Dumper;
use Getopt::Long;
use POSIX;
use IO::Socket::Multicast;
use JSON;

# Native Maxmind library - http://www.maxmind.com/download/geoip/api/perl/
# requires: http://www.maxmind.com/app/c
use Geo::IP;

# set these to the same port and multicast (or unicast) address as the detector
use constant GROUP => '226.1.1.2';
use constant PORT  => '2000';

my %ipc_source :shared;
my %ipc_customer :shared;
my $time_to_die :shared = 0;
my $debug;
my $foreground=0;

# determines how often you want to aggregage and write-out stats dumps
my $interval = 60;

# you can get the binary format GeoLiteCity.dat from Maxmind
# http://www.maxmind.com/app/geolitecity
my $gi = Geo::IP->open("/usr/local/GeoLiteCity.dat",GEOIP_MEMORY_CACHE | GEOIP_CHECK_CACHE);

# adjust this to the path where you want to keep the 
sub PATH {'/tmp/'}

$|=1;

GetOptions(
  "debug" => \$debug,
  "foreground" => \$foreground,
  "interval=s" => \$interval,
);


main();
exit();

sub main() {

  # daemonize unless running in foreground
  unless ($foreground){
    daemonize();
  }

  # prepare data acquisition thread
  threads->new(\&get_data);

  while (! $time_to_die ) {

    # record time started to help evenly space runs
    my $start_run = time();
    my $next_run = $start_run + $interval;

    # de-serialize latest copy of source address structure
    # execute this in a isolated scope so that lock goes out of scope
    {
      my $source_distance;

      # lock data structure to prevent other thread from updating it
      lock(%ipc_source); 

      # open coordinates file for graph generation
      open(CRDS, ">".PATH."/coords.txt.tmp");

      # calculate great circle distance between each source IP and local POP
      foreach my $key (keys %ipc_source) { 

        eval {
        my $r = $gi->record_by_addr($key);

        # write raw entry to coordinates file             
        print CRDS $key.",".$ipc_source{$key}.",".$r->latitude.",".$r->longitude."\n";
        };
        if ($@) {
          print CRDS $key.",".$ipc_source{$key}.",0,0\n";
        }
      }

      # close coordinate file
      close CRDS;
      system("mv ".PATH."/coords.txt.tmp ".PATH."/coords.txt");

      # clean out structure for next sample period
      %ipc_source = ();
    }

    # sleep to make the interval
    while((my $time_left = ($next_run - time())) > 0) {
      sleep($time_left);
    }
  }
  threads->join();
  return;
}

# fetch data from UDP multicast
sub get_data() {

  # set up our multicast listener
  # note: this will receive unicast fine too
  my $sock = IO::Socket::Multicast->new(LocalPort=>PORT,ReuseAddr=>1);
  $sock->mcast_add(GROUP) || die "Couldn't set group: $!\n";


  while (  ! $time_to_die  ) {
    my $data;
    next unless $sock->recv($data,1500);

    # decode JSON
    eval {
      my $obj = decode_json $data;
      print Dumper $obj;
      foreach my $ip (keys %{$obj->{data}}) {
        my $count = $obj->{data}->{$ip};
        lock(%ipc_source);
        $ipc_source{$ip}+=$count;
      }
    };

  }

  # done!
  threads->exit();
}

# daemonize application
sub daemonize {

  chdir '/' or die "Can't chdir to /: $!";
  open STDIN, '/dev/null' or die "Can't read /dev/null: $!";
  open STDOUT, '>/dev/null';

  # fork and exit parent
  my $pid = fork();
  exit if $pid;
  die "Couldn't fork: $!" unless defined ($pid);
  POSIX::setsid() || die ("$0 can't start a new session: $!");        
  open STDERR, '>&STDOUT' or die "Can't dup stdout: $!";
  
  # signal handlers
  $SIG{KILL} = \&handler;
}

sub handler {
  $time_to_die = 1;
}
