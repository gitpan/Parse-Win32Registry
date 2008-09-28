#!/usr/bin/perl
use strict;
use warnings;

binmode(STDOUT, ":utf8");

use File::Basename;
use Getopt::Long;
use Parse::Win32Registry qw(iso8601);

Getopt::Long::Configure('bundling');

GetOptions('last|l=f'  => \my $period,
           'recurse|r' => \my $recurse,
           'values|v'  => \my $show_values);

my $filename = shift or die usage();
my $initial_key_name = shift;

my $registry = Parse::Win32Registry->new($filename)
    or die "'$filename' is not a registry file\n";
my $root_key = $registry->get_root_key
    or die "Could not get root key of '$filename'\n";

if (!defined($root_key->get_timestamp)) {
    die "'$filename' must be an NT-based registry file"
}

if (defined($initial_key_name)) {
    $root_key = $root_key->get_subkey($initial_key_name);
    if (!defined($root_key)) {
        die "Could not locate the key '$initial_key_name' in '$filename'\n";
    }
}

warn "Ordering keys...\n";

my $first_timestamp = 0;
my $last_timestamp = 0;
my %keys_by_timestamp = ();

traverse($root_key);

sub traverse {
    my $key = shift;
    
    my $timestamp = $key->get_timestamp;
    push @{$keys_by_timestamp{$timestamp}}, $key;
    $first_timestamp = $timestamp if $timestamp < $first_timestamp;
    $last_timestamp = $timestamp if $timestamp > $last_timestamp;

    foreach my $subkey ($key->get_list_of_subkeys) {
        traverse($subkey);
    }
}

if ($period) {
    $first_timestamp = $last_timestamp - $period * 86400;
}

foreach my $timestamp (sort keys %keys_by_timestamp) {
    next if $timestamp < $first_timestamp;
    foreach my $key (@{$keys_by_timestamp{$timestamp}}) {
        print iso8601($timestamp), "\t", $key->get_path, "\n";
        if ($show_values) {
            foreach my $value ($key->get_list_of_values) {
                print "\t", $value->as_string, "\n";
            }
            print "\n";
        }
    }
}

sub usage {
    my $script_name = basename $0;
    return <<USAGE;
$script_name for Parse::Win32Registry $Parse::Win32Registry::VERSION

$script_name <filename> [subkey] [-l <number>] [-v]
    -l or --last        display only the last <number> days
                        of registry activity
    -v or --values      display values
USAGE
}
