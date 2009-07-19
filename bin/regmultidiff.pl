#!/usr/bin/perl
use strict;
use warnings;

use File::Basename;
use Getopt::Long;
use Parse::Win32Registry 0.50 qw( make_multiple_subtree_iterator
                                  compare_multiple_keys
                                  compare_multiple_values
                                  hexdump );

binmode(STDOUT, ':utf8');

Getopt::Long::Configure('bundling');

GetOptions('values|v'  => \my $show_values,
           'hexdump|x' => \my $show_hexdump,
           'all|a'     => \my $show_all);

my $show_keys = 1;

my @filenames = ();
my @root_keys = ();
my @start_keys = ();
my $initial_key_path;

if (@ARGV) {
    while (my $filename = shift) {
        if (-r $filename) {
            my $registry = Parse::Win32Registry->new($filename);
            if (defined $registry) {
                my $root_key = $registry->get_root_key;
                if (defined $root_key) {
                    push @root_keys, $root_key;
                    push @filenames, $filename;
                }
            }
        }
        else {
            # If $filename is not a readable file, assume it is a key path:
            $initial_key_path = $filename;
        }
    }
}
else {
    die usage();
}

if (@root_keys < 2) {
    die "Specify two or more filenames\n";
}

@start_keys = @root_keys;
if ($initial_key_path) {
    @start_keys = map { $_->get_subkey($initial_key_path) || undef } @root_keys;
}

my $num_start_keys = grep { defined } @start_keys;
if ($num_start_keys < 2) {
    die "Could not locate the key '$initial_key_path'\nin at least two of the specified files\n";
}

my $subtree_iter = make_multiple_subtree_iterator(@start_keys);
my $batch_size = @start_keys;

for (my $num = 0; $num < $batch_size; $num++) {
    print "[$num]:\tFILE\t'$filenames[$num]'\n";
}

my $key_shown;
my $keys_ref = \@start_keys;
my $values_ref;
do {
    my @keys = @$keys_ref;
    my $any_key = (grep { defined } @keys)[0];
    die "Unexpected error: no keys!" if !defined $any_key;

    if (defined $values_ref) {
        my @values = @$values_ref;
        my $any_value = (grep { defined } @values)[0];
        die "Unexpected error: no values!" if !defined $any_value;

        my @changes = compare_multiple_values(@values);
        my $num_changes = grep { $_ } @changes;
        if ($num_changes > 0 && $show_values) {
            if (!defined $key_shown || $key_shown ne $any_key->get_path) {
                print "[*]:\t\t", $any_key->as_string, ":\n";
                $key_shown = $any_key->get_path;
            }
            for (my $num = 0; $num < $batch_size; $num++) {
                my $next_change = $changes[$num + 1];
                if ($changes[$num] || $show_all
                                   || defined $next_change
                                           && $next_change eq 'DELETED') {
                    print "[$num]:\t$changes[$num]\t";
                    if (defined $values[$num]) {
                        if (!$show_hexdump) {
                            print $values[$num]->as_string, "\n";
                        }
                        else {
                            my $value_name = $values[$num]->get_name;
                            $value_name = "(Default)" if $value_name eq "";
                            my $value_type = $values[$num]->get_type_as_string;
                            print "$value_name ($value_type):\n";
                            print hexdump($values[$num]->get_raw_data);
                        }
                    }
                    else {
                        print "\n";
                    }
                }
            }
        }
    }
    else {
        my @changes = compare_multiple_keys(@keys);
        my $num_changes = grep { $_ } @changes;
        if ($num_changes > 0 && $show_keys) {
            for (my $num = 0; $num < $batch_size; $num++) {
                my $next_change = $changes[$num+1];
                if ($changes[$num] || $show_all
                                   || defined $next_change
                                           && $next_change eq 'DELETED') {
                    print "[$num]:\t$changes[$num]\t";
                    if (defined $keys[$num]) {
                        print $keys[$num]->as_string;
                        $key_shown = $keys[$num]->get_path;
                    }
                    elsif ($changes[$num] eq 'DELETED') {
                        print $keys[$num-1]->as_string;
                        $key_shown = $keys[$num-1]->get_path;
                    }
                    print "\n";
                }
            }
        }
    }
}
while (($keys_ref, $values_ref) = $subtree_iter->get_next);

sub usage {
    my $script_name = basename $0;
    return <<USAGE;
$script_name for Parse::Win32Registry $Parse::Win32Registry::VERSION

Compares two or more registry files.

$script_name <file1> <file2> <file3> ... [<subkey>] [-v] [-x] [-a]
    -v or --values      display values
    -x or --hexdump     display value data as a hex dump
    -a or --all         show all keys and values preceding and following
                        any changes
USAGE
}
