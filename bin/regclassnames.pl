#!/usr/bin/perl
use strict;
use warnings;

binmode(STDOUT, ':utf8');

use File::Basename;
use Parse::Win32Registry qw(unpack_unicode_string);

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

    if (my $class_name = $key->get_class_name) {
        print $key->get_path, " \"$class_name\"\n";
    }
    
    foreach my $subkey ($key->get_list_of_subkeys) {
        traverse($subkey);
    }
}

sub usage {
    my $script_name = basename $0;
    return <<USAGE;
$script_name for Parse::Win32Registry $Parse::Win32Registry::VERSION

Displays keys in a registry file that have a class name.

$script_name <filename> [subkey]
USAGE
}
