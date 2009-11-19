#!/usr/bin/env perl

# check_sysstat.pl
# Author: Jeff Goldschrafe
# Version: 0.20
# 
# This Nagios plugin allows you to query the values of one or more sa/sar
# counters, compare them to specified thresholds, and return the performance
# data to Nagios.
# 
# It may or may not work with sa on Solaris or any other Unix. I'm very much
# welcoming any fixes for other platforms if you notice anything wrong.
# 
# Limitations:
# - You can query multiple counter names and multiple device names. There is not
#   any way at this time to only query specific device names on specific
#   counters. You will need to run multiple checks.
# 
# This file is distributed under the terms of the GNU General Public License.

use strict;
use warnings;

use Error qw(:try);
use Nagios::Plugin;
use Text::Glob qw(glob_to_regex);

use Data::Dumper;


# Aggregate together data points over a specified sampling interval and boil
# them down to a single average per counter/device over the sampling period
sub average_data {
    my ($sa_data) = @_;
    
    my %results = ();
    
    foreach my $dp (@$sa_data) {
        my $counter = $dp->{'counter'};
        my $threshold_index = $dp->{'threshold_index'};
        my $device = $dp->{'device'};
        my $value = $dp->{'value'};
        
        $results{$counter} ||= {};
        $results{$counter}{$device} ||= {
            average         => 0,
            threshold_index => $threshold_index,
            samples         => 0,
            total           => 0
        };
        
        $results{$counter}{$device}{'samples'}++;
        $results{$counter}{$device}{'total'} += $value;
        $results{$counter}{$device}{'average'} =
          $results{$counter}{$device}{'total'} /
          $results{$counter}{$device}{'samples'};
    }
    
    return \%results;
}


# Returning a hash containing all counter names and associated devices
sub get_counters {
    my ($sa_raw_logs) = @_;
    
    my %counters = ();
    
    my @sa_log_lines = split(/\n+/, $sa_raw_logs);
    foreach my $line (@sa_log_lines) {
        my @fields = split("\t", $line);
        if (scalar @fields == 6) {
            my ($hostname, $interval, $timestamp, $device, $counter,
              $value) = @fields;
            
            $counters{$counter} ||= {};
            $counters{$counter}{$device} = 1;
        }
    }
    
    return \%counters;
}


# Initialize the plugin object and set up Nagios::Plugin::Getopt
sub init_plugin {
    my $np = Nagios::Plugin->new(
      usage => "Usage: %s"
    );
    
    $np->add_arg(
      spec => 'counter|C=s@',
      help => "-C, --counter=STRING\n" .
              "   Counter name to probe. You may specify multiple counter\n" .
              "   names by using multiple -C options, or by using shell\n" .
              "   wildcards like * or ?. When using multiple -C options,\n" .
              "   you must specify a warning and critical range for each,\n" .
              "   in order."
    );

    $np->add_arg(
      spec => 'critical|c=s@',
      help => "-c, --critical=THRESHOLD\n" .
              "    Generate a critical status when the corresponding counter\n" .
              "    is outside this threshold."
    );

    $np->add_arg(
      spec => 'device|d=s@',
      help => "-d, --device=STRING\n" .
              "    For all provided counters, only include the specified\n" .
              "    device. You may specify multiple device names by using\n" .
              "    multiple -d options, or by using shell wildcards like\n" .
              "    * or ?. If multiple options are specified, match any\n" .
              "    of the provided device patterns."
    );
    
    $np->add_arg(
      spec => 'exclude-device|D=s@',
      help => "-D, --exclude-device=STRING\n" .
              "    Same as above, except exclude the specified devices from\n" .
              "    being checked."
    );
    
    $np->add_arg(
      spec => 'ignore-thresholds|i',
      help => "--ignore-thresholds\n" .
              "    Ignore all thresholds; return OK status with performance\n" .
              "    data only."
    );
    
    $np->add_arg(
      spec => 'list-counters|L',
      help => "-L, --list-counters\n" .
              "    Provide a list of counters (useful for testing). The\n" .
              "    plugin will not produce any other output."
    );

    $np->add_arg(
      spec => 'minutes|m=i',
      help => "-m, --minutes=INTEGER\n" .
              "    Number of minutes to average. Be sure that this is no less\n" .
              "    than the sa data collection interval for your counters, or\n" .
              "    unpredictable things may happen."
    );
    
    $np->add_arg(
      spec => 'sadf-path=s',
      help => "--sadf-log-path=PATH\n" .
              "    The path to sadf (default /usr/bin/sadf)"
    );
    
    $np->add_arg(
      spec => 'sa-log-dir=s',
      help => "--sa-log-dir=DIR\n" .
              "    The directory in which sa stores its log files (default\n" .
              "    /var/log/sysstat)"
    );
    
    $np->add_arg(
      spec => 'warning|w=s@',
      help => "-w, --warning=THRESHOLD\n" .
              "    Generate a warning status when the corresponding counter\n" .
              "    is outside this threshold."
    );

    return $np;
}


# Parse and filter logs in one step for speed; this function is expensive
# enough as it is
sub parse_logs {
    my ($sa_raw_logs, $args) = @_;
    
    my $counters = $args->{'counters'};
    my $devices = $args->{'devices'};
    my $exclude_devices = $args->{'exclude_devices'};
    my $minutes = $args->{'minutes'};
    
    my $start_timestamp = time() - ($minutes * 60);
    my %counters_found = ();
    my @log_data_entries = ();
    
    # It's very, very slow to call glob_to_regex() on every run through the
    # loop; we're going to cache the generated regex for each glob pattern
    # and reference them in the lookup table later
    my %regex_cache = ();
    foreach my $p (@$counters, @$devices, @$exclude_devices) {
        $regex_cache{$p} = glob_to_regex($p);
    }

    # Iterate over all of the data raw data points from the logs, extract
    # the fields, and match them against the specified criteria 
    my @sa_log_lines = split(/\n+/, $sa_raw_logs);   
    foreach my $line (@sa_log_lines) {
        my @fields = split("\t", $line);
        if (scalar @fields == 6) {
            my ($hostname, $interval, $timestamp, $device, $counter,
              $value) = @fields;
            
            # Check whether or not the counter matches what we're searching for
            my $counter_regex_pass = 0;
            my $threshold_index = 0;
            my $num_counters = scalar @$counters;
            foreach my $c (@$counters) {
                my $regex = $regex_cache{$c};
                if ($counter =~ /$regex/) {
                    $counter_regex_pass = 1;
                    last;
                }

                $threshold_index++;
            }

            next unless $counter_regex_pass;

            # Check whether or not the device matches what we're searching for
            my $device_regex_pass = (scalar @$devices == 0);
            foreach my $d (@$devices) {
                my $regex = $regex_cache{$d};
                if ($device =~ /$regex/) {
                    $device_regex_pass = 1;
                    last;
                }
            }

            next unless $device_regex_pass;
           
            # Check whether or not the device matches one of the patterns
            # designating devices we don't want
            my $exclude_device_regex_pass = (scalar @$exclude_devices == 0);
            foreach my $xd (@$exclude_devices) {
                my $regex = $regex_cache{$xd};
                if ($device !~ /$regex/) {
                    $exclude_device_regex_pass = 1;
                    last;
                }
            }

            next unless $exclude_device_regex_pass;
           
            # Add the data point to our result set if it matches all of the
            # above criteria and is within the specified sampling period 
            if (($timestamp >= $start_timestamp)
              && ($device_regex_pass)
              && ($exclude_device_regex_pass)
              && ($counter_regex_pass)
            ) {
                my %data_point = (
                  hostname        => $hostname,
                  interval        => $interval,
                  timestamp       => $timestamp,
                  device          => $device,
                  counter         => $counter,
                  value           => $value,
                  threshold_index => $threshold_index
                );
                    
                push @log_data_entries, \%data_point;
                $counters_found{$threshold_index} = 1;
            }
        }
    }
    
    # Validate that all passed glob patterns matched at least one counter
    # and throw an exception if this is not true
    for (my $i = 0; $i < scalar @$counters; $i++) {
        unless ($counters_found{$i}) {
            my $c = $counters->[$i];
            throw Error::Simple("No data points found for counter '$c'");
        }
    }

    return \@log_data_entries;    
}


# This plugin may be running early in the morning, or a sampling period may
# be specified which requires us to backtrack a day in the logs. We will always
# (rather naively, and probably at the cost of speed) read one day back in
# addition to today.
sub read_logs {
    my ($opts) = @_;
   
    my $sadf = $opts->{'sadf'}; 
    my $sa_log_dir = $opts->{'sa_log_dir'};
    
    my @sa_log_files = ();
    {
        my ($ts, $tm, $th, $td) = localtime(time());
        my ($ys, $ym, $yh, $yd) = localtime(time() - (24 * 60 * 60));

        my $yd_log_file = "$sa_log_dir/sa$yd";
        if (-f $yd_log_file) {
            push @sa_log_files, $yd_log_file;
        }
    }

    my $sadf_output = '';
    foreach my $log (@sa_log_files) {
        $sadf_output .= `$sadf $log -- -A`;
    }
    $sadf_output .= `$sadf -- -A`;
    
    return $sadf_output;
}



sub sanity_check {
    my ($opts) = @_;

    my $counters = $opts->{'counters'};
    my $critical_thresholds = $opts->{'critical_thresholds'};
    my $ignore_thresholds = $opts->{'ignore_thresholds'};
    my $sadf = $opts->{'sadf'};
    my $sa_log_dir = $opts->{'sa_log_dir'};
    my $warning_thresholds = $opts->{'warning_thresholds'};
    
    unless (-f $sadf) {
        throw Error::Simple("$sadf does not exist!");
    }

    unless (-x $sadf) {
        throw Error::Simple("$sadf is not executable!");
    }

    unless (-d $sa_log_dir or -l $sa_log_dir) {
        throw Error::Simple("$sa_log_dir is not a directory!");
    }

    if (scalar @$counters == 0) {
        throw Error::Simple("No counters to check!");
    }

    unless ($ignore_thresholds) {
        if ($critical_thresholds && @$critical_thresholds != @$counters) {
            throw Error::Simple(
              "Number of critical thresholds does not match number of counters");
        }
        
        if ($warning_thresholds && @$warning_thresholds != @$counters) {
            throw Error::Simple(
              "Number of warning thresholds does not match number of counters");
        }
    }

}



my $np = init_plugin();
my $npo = $np->opts();
$npo->getopts();

my @critical_messages = ();
my @unknown_messages = ();
my @warning_messages = ();

# We handle all of our option defaults down here because the
# Nagios::Plugin::Getopt implementation stacks array values onto the default
# instead of replacing it
my %opts;
$opts{'counters'} = $npo->get('counter') || [];
$opts{'critical_thresholds'} = $npo->get('critical') || [];
$opts{'devices'} = $npo->get('device') || [];
$opts{'exclude_devices'} = $npo->get('exclude-device') || [];
$opts{'ignore_thresholds'} = $npo->get('ignore-thresholds') || 0;
$opts{'list_counters'} = $npo->get('list-counters') || 0;
$opts{'minutes'} = $npo->get('minutes') || 10;
$opts{'sadf'} = $npo->get('sadf-path') || '/usr/bin/sadf';
$opts{'sa_log_dir'} = $npo->get('sa-log-dir') || '/var/log/sysstat';
$opts{'warning_thresholds'} = $npo->get('warning') || [];

# Run sanity checks and abort with UNKNOWN if anything goes wrong
try {
    sanity_check(\%opts);
} catch Error with {
    my $ex = shift;
    $np->nagios_exit(UNKNOWN, $ex);
};

# Read raw log data
my $sa_raw_logs = read_logs(\%opts);

# Preempt all other processing if user has chosen to list counters
if ($opts{'list_counters'}) {
    my $counter_list = get_counters($sa_raw_logs);

    foreach my $c (sort keys %$counter_list) {
        my $counter_devices = join(", ", sort keys %{$counter_list->{$c}});
        print "$c ($counter_devices)\n";
    }
    
    exit 2;
}

# Parse logs from raw log data
my $sa_data;
try {
    $sa_data = parse_logs($sa_raw_logs, \%opts);
} catch Error with {
    my $ex = shift;
    push @unknown_messages, $ex;
};

# Average the data across the time range chosen
my $sa_data_averaged = average_data($sa_data);

# Run all checks and add all performance data
foreach my $counter (sort keys %$sa_data_averaged) {
    foreach my $device (sort keys %{$sa_data_averaged->{$counter}}) {
        my $label = "$counter\[$device\]";
        my $d = $sa_data_averaged->{$counter}->{$device};

        # Add performance data always
        $np->add_perfdata(
          label => $label,
          value => $d->{'average'}
        );
        
        # If --ignore-thresholds is set, user only wants performance data;
        # do not run any threshold checks against the retrieved data
        unless ($opts{'ignore_thresholds'}) {
            my $i = $d->{'threshold_index'};

            $np->set_thresholds(
              critical => $opts{'critical_thresholds'}->[$i],
              warning  => $opts{'warning_thresholds'}->[$i]
            );

            my $check_result = $np->check_threshold($d->{'average'});
            
            if ($check_result == CRITICAL) {
                push @critical_messages, "$label out of range";
            } elsif ($check_result == WARNING) {
                push @warning_messages, "$label out of range";
            }
        }
    }
}

# Display final output and exit
if (@unknown_messages) {
    $np->nagios_exit(UNKNOWN, join(' ', @unknown_messages));
} elsif (@critical_messages) {
    $np->nagios_exit(CRITICAL, join(' ', @critical_messages));
} elsif (@warning_messages) {
    $np->nagios_exit(WARNING, join(' ', @warning_messages));
}

$np->nagios_exit(OK, 'All counters within specified thresholds.');

