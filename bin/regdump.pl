#!/usr/bin/perl
use strict;
use warnings;

binmode(STDOUT, ':utf8');

use File::Basename;
use Getopt::Long;
use Parse::Win32Registry qw(hexdump);

Getopt::Long::Configure('bundling');

GetOptions('recurse|r'  => \my $recurse,
           'values|v'   => \my $show_values,
           'hexdump|x'  => \my $show_hexdump);

my $filename = shift or die usage();
my $initial_key_name = shift;

my $registry = Parse::Win32Registry->new($filename)
    or die "'$filename' is not a registry file\n";
my $root_key = $registry->get_root_key
    or die "Could not get root key of '$filename'\n";

if (defined($initial_key_name)) {
    $root_key = $root_key->get_subkey($initial_key_name);
    if (!defined($root_key)) {
        die "Could not locate the key '$initial_key_name' in '$filename'\n";
    }
}

traverse($root_key);

sub traverse {
    my $key = shift;

    print $key->as_string, "\n";
    
    # Display names of subkeys if we are not descending the tree
    if (!$recurse) {
        foreach my $subkey ($key->get_list_of_subkeys) {
            print "..\\", $subkey->get_name, "\n";
        }
    }
    
    if ($show_values) {
        foreach my $value ($key->get_list_of_values) {
            if (!$show_hexdump) {
                print $value->as_string, "\n";
            }
            else {
                my $value_name = $value->get_name;
                $value_name = "(Default)" if $value_name eq "";
                my $value_type = $value->get_type_as_string;
                print "$value_name ($value_type):\n";
                print hexdump($value->get_raw_data);
            }
        }
        print "\n";
    }

    if ($recurse) {
        foreach my $subkey ($key->get_list_of_subkeys) {
            traverse($subkey);
        }
    }
}

sub usage {
    my $script_name = basename $0;
    return <<USAGE;
$script_name for Parse::Win32Registry $Parse::Win32Registry::VERSION

Dumps the keys and values of a registry file.

$script_name <filename> [subkey] [-r] [-v] [-x]
    -r or --recurse     traverse all child keys from the root key
                        or the subkey specified
    -v or --values      display values
    -x or --hexdump     display value data as a hex dump
USAGE
}
