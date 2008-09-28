use strict;
use warnings;

use Test::More 'no_plan';
use Parse::Win32Registry 0.40;

sub find_file
{
    my $filename = shift;
    return -d 't' ? "t/$filename" : $filename;
}

{
    my @tests = (
        [
            'fake_user_dat.rf', 'HKEY_USERS', '',
            ['.DEFAULT', 'Software'],
        ],
        [
            'fake_system_dat.rf', 'HKEY_LOCAL_MACHINE', '',
            ['Software', 'System'],
        ],
        [
            'fake_sam.rf', 'HKEY_LOCAL_MACHINE\\SAM', 'SAM',
            ['SAM'],
        ],
        [
            'fake_security.rf', 'HKEY_LOCAL_MACHINE\\SECURITY', 'SECURITY',
            ['Cache', 'Policy', 'RXACT'],
        ],
        [
            'fake_software.rf', 'HKEY_LOCAL_MACHINE\\SOFTWARE', '$$$PROTO.HIV',
            ['Microsoft', 'Policies'],
        ],
        [
            'fake_system.rf', 'HKEY_LOCAL_MACHINE\\SYSTEM', '$$$PROTO.HIV',
            ['ControlSet001', 'Select'],
        ],
        [
            'fake_ntuser_dat.rf', 'HKEY_CURRENT_USER', '$$$PROTO.HIV',
            ['Control Panel', 'Environment', 'Software'],
        ],
        [
            'fake_usrclass_dat.rf', 'HKEY_CLASSES_ROOT', 'S-1-5-21-123456789-123456789-123456789-1000_Classes',
            ['CLSID'],
        ],
    );

    foreach my $test (@tests) {
        my ($filename, $virtual_root, $original_root_key_name, $key_names) =
            @$test;
        $filename = find_file($filename);

        my $registry = Parse::Win32Registry->new($filename);
        ok(defined($registry), 'registry defined');
        my $root_key = $registry->get_virtual_root_key;
        ok(defined($root_key), 'root key defined');
        is($root_key->get_name, $virtual_root,
            qq{root key get_name eq "$virtual_root"});
        isnt($root_key->get_name, $original_root_key_name,
            qq{root key get_name ne "$original_root_key_name"});

        foreach my $key_name (@$key_names) {
            my $key = $root_key->get_subkey($key_name);
            my $virtual_path = "$virtual_root\\$key_name";
            is($key->get_path, $virtual_path,
                qq{subkey get_path eq "$virtual_path"});
        }
    }
}
