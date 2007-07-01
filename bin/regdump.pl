use strict;
use warnings;

binmode(STDOUT, ':utf8');

use File::Basename;
use Getopt::Long;
use Parse::Win32Registry;

Getopt::Long::Configure('bundling');

GetOptions('quiet|q'   => \my $quiet,
           'recurse|r' => \my $recurse);

my $filename = shift or die usage();
my $initial_key_name = shift;

my $registry = Parse::Win32Registry->new($filename);
my $root_key = $registry->get_root_key;

if (defined($initial_key_name)) {
    $root_key = $root_key->get_subkey($initial_key_name);
    if (!defined($root_key)) {
        die "Could not locate the key '$initial_key_name' in '$filename'\n";
    }
}

traverse($root_key);

sub traverse {
    my $key = shift;

    # Put a gap between keys if we are displaying values
    print "\n" if !$quiet;

    print $key->as_string, "\n";
    
    # Display names of subkeys if we are not descending the tree
    if (!$recurse) {
        foreach my $subkey ($key->get_list_of_subkeys) {
            print "..\\", $subkey->get_name, "\n";
        }
    }
    
    # Display values unless this has been suppressed
    if (!$quiet) {
        foreach my $value ($key->get_list_of_values) {
            print $value->as_string, "\n";
        }
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

$script_name <filename> [subkey] [-r] [-q]
    -r or --recurse     traverse all child keys from the root key
                        or the subkey specified
    -q or --quiet       do not display values
USAGE
}
