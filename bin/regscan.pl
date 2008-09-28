#!/usr/bin/perl
use strict;
use warnings;

binmode(STDOUT, ':utf8');

use File::Basename;
use Getopt::Long;
use Parse::Win32Registry;

Getopt::Long::Configure('bundling');

GetOptions('debug|d'   => \my $debug_mode,
           'silent|s'  => \my $suppress_warnings,
           'hexdump|x' => \my $show_hexdump);

my $filename = shift or die usage();

if ($suppress_warnings) {
    Parse::Win32Registry->disable_warnings;
}
else {
    Parse::Win32Registry->enable_warnings;
}

my $registry = Parse::Win32Registry->new($filename)
    or die "'$filename' is not a registry file\n";

while (my $entry = $registry->get_next_entry) {
    if ($debug_mode) {
        print $entry->parse_info, "\n";
    }
    else {
        print $entry->as_string, "\n";
    }
    print $entry->as_hexdump if $show_hexdump;
}

sub usage {
    my $script_name = basename $0;
    return <<USAGE;
$script_name for Parse::Win32Registry $Parse::Win32Registry::VERSION

$script_name <filename> [-d] [-s] [-x]
    -d or --debug       show the technical information for an entry
                        instead of the string representation
    -s or --silent      suppress the display of warning messages
                        for invalid keys and values
    -x or --hexdump     show the on-disk entries as a hex dump
USAGE
}
