use strict;
use warnings;

binmode(STDOUT, ':utf8');

use File::Basename;
use Getopt::Long;
use Parse::Win32Registry;

Getopt::Long::Configure('bundling');

GetOptions('values|v' => \my $show_values);

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
    my $depth = shift || 0;

    print "  " x $depth;
    print "" if $depth > 0;
    print $key->get_name;
    if (defined($key->get_timestamp)) {
        print " [", $key->get_timestamp_as_string, "]"
    }
    print "\n";

    if ($show_values) {
        foreach my $value ($key->get_list_of_values) {
            print "  " x $depth;
            print "  ", $value->as_string, "\n";
        }
    }
    
    foreach my $subkey ($key->get_list_of_subkeys) {
        traverse($subkey, $depth + 1);
    }
}

sub usage {
    my $script_name = basename $0;
    return <<USAGE;
$script_name for Parse::Win32Registry $Parse::Win32Registry::VERSION

$script_name <filename> [subkey] [-v]
    -v or --values      display values
USAGE
}
