use strict;
use warnings;
no warnings 'utf8';

binmode(STDOUT, ':utf8');

use File::Basename;
use Getopt::Long;
use Parse::Win32Registry;

Getopt::Long::Configure('bundling');

GetOptions('key|k'   => \my $search_keys,
           'value|v' => \my $search_values,
           'data|d'  => \my $search_data);

my $filename = shift or die usage();
my $regexp = shift or die usage();

if (!$search_keys && !$search_values && !$search_data) {
    warn usage();
    die "\nYou need to specify at least one of -k, -v, or -d\n";
}

my $registry = Parse::Win32Registry->new($filename);
my $root_key = $registry->get_root_key;

traverse($root_key);

sub traverse {
    my $key = shift;
    
    if ($search_keys) {
        foreach my $subkey ($key->get_list_of_subkeys) {
            if ($subkey->get_name =~ /$regexp/oi) {
                print "KEY\t", $subkey->get_path, "\n";
            }
        }
    }
    
    if ($search_values || $search_data) {
        foreach my $value ($key->get_list_of_values) {
            if ($search_values && $value->get_name =~ /$regexp/oi) {
                print "VALUE\t", $key->get_path, "\\", $value->as_string, "\n";
            }
            if ($search_data && $value->get_data =~ /$regexp/oi) {
                print "DATA\t", $key->get_path, "\\", $value->as_string, "\n";
            }
        }
    }
    
    foreach my $subkey ($key->get_list_of_subkeys) {
        traverse($subkey);
    }
}

sub usage {
    my $script_name = basename $0;
    return <<USAGE;
$script_name for Parse::Win32Registry $Parse::Win32Registry::VERSION

$script_name <filename> <search-string> [-k] [-v] [-d]
    -k or --key       search key names for a match
    -v or --value     search value names for a match
    -d or --data      search value data for a match
USAGE
}
