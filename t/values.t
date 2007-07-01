use strict;
use warnings;

use Test::More 'no_plan';

use Data::Dumper;
$Data::Dumper::Useqq = 1;
$Data::Dumper::Terse = 1;
$Data::Dumper::Indent = 0;

use Parse::Win32Registry qw(:REG_); # :REG_ constants are tested elsewhere

die 'Incorrect version' if $Parse::Win32Registry::VERSION != '0.30';

sub find_file
{
    my $filename = shift;
    return -d 't' ? "t/$filename" : $filename;
}

sub run_value_tests
{
    my $key = shift;
    my @tests = @_;

    foreach my $test (@tests) {
        my ($name, $type, $type_as_string, $data, $data_as_string)
            = @{ $test };
        my $value = $key->get_value($name);
        ok(defined($value), 'value defined');
        is($value->get_name, $name, 'get_name eq ' . Dumper($name));
        is($value->get_type, $type, "get_type == $type");
        is($value->get_type_as_string, $type_as_string,
            "get_type_as_string eq '$type_as_string'");
        if (defined($data)) {
            if ($type == REG_DWORD) {
                cmp_ok($value->get_data, '==', $data, "get_data == $data");
            }
            else {
                is($value->get_data, $data, 'get_data eq ' . Dumper($data));
            }
        }
        else {
            ok(!defined($value->get_data), 'get_data undefined');
        }
        is($value->get_data_as_string, $data_as_string,
            'get_data_as_string eq ' . Dumper($data_as_string));
        my $name_or_default = $name eq '' ? '(Default)' : $name;
        my $value_as_string
            = "$name_or_default ($type_as_string) = $data_as_string";
        is($value->as_string, $value_as_string,
            'as_string eq ' . Dumper($value_as_string));
    }
}

{
    my $filename = find_file('win95_value_tests.rf');

    my $registry = Parse::Win32Registry->new($filename);
    ok(defined($registry), 'registry defined');
    isa_ok($registry, 'Parse::Win32Registry::Win95::File');

    my $root_key = $registry->get_root_key;
    ok(defined($registry), 'root key defined');
    isa_ok($root_key, 'Parse::Win32Registry::Win95::Key');
    is($root_key->get_name, '', 'root key name');

    my $key1 = $root_key->get_subkey('key1');
    ok(defined($key1), 'key1 defined');
    is($key1->get_name, 'key1', 'key1 name');

    my @tests = (
        ['sz1', REG_SZ, 'REG_SZ', 'www.perl.com', 'www.perl.com'],
        ['sz2', REG_SZ, 'REG_SZ', 'www.perl.com', 'www.perl.com'],
        ['sz3', REG_SZ, 'REG_SZ', '', '(no data)'],
        ['sz4', REG_SZ, 'REG_SZ', '', '(no data)'],
        ['expand_sz1', REG_EXPAND_SZ, 'REG_EXPAND_SZ', 'www.perl.com', 'www.perl.com'],
        ['expand_sz2', REG_EXPAND_SZ, 'REG_EXPAND_SZ', 'www.perl.com', 'www.perl.com'],
        ['expand_sz3', REG_EXPAND_SZ, 'REG_EXPAND_SZ', '', '(no data)'],
        ['expand_sz4', REG_EXPAND_SZ, 'REG_EXPAND_SZ', '', '(no data)'],
        ['binary1', REG_BINARY, 'REG_BINARY', "\x01\x02\x03\x04\x05\x06\x07\x08", '01 02 03 04 05 06 07 08'],
        ['binary2', REG_BINARY, 'REG_BINARY', '', '(no data)'],
        ['dword1', REG_DWORD, 'REG_DWORD', 67305985, '0x04030201 (67305985)'],
        ['dword2', REG_DWORD, 'REG_DWORD', undef, '(invalid data)'],
        ['dword3', REG_DWORD, 'REG_DWORD', undef, '(invalid data)'],
        ['dword4', REG_DWORD, 'REG_DWORD', undef, '(invalid data)'],
        ['dword5', REG_DWORD, 'REG_DWORD', 0, '0x00000000 (0)'],
        ['dword6', REG_DWORD, 'REG_DWORD', 0x7fffffff, '0x7fffffff (2147483647)'],
        ['dword7', REG_DWORD, 'REG_DWORD', 0x80000000, '0x80000000 (2147483648)'],
        ['dword8', REG_DWORD, 'REG_DWORD', 0xffffffff, '0xffffffff (4294967295)'],
        ['multi_sz1', REG_MULTI_SZ, 'REG_MULTI_SZ', "String1\c@String2\c@String3\c@\c@", '[0] String1 [1] String2 [2] String3'],
        ['multi_sz2', REG_MULTI_SZ, 'REG_MULTI_SZ', "String1\c@\c@", '[0] String1'],
        ['multi_sz3', REG_MULTI_SZ, 'REG_MULTI_SZ', "String1\c@", '[0] String1'],
        ['multi_sz4', REG_MULTI_SZ, 'REG_MULTI_SZ', "String1", '[0] String1'],
        ['multi_sz5', REG_MULTI_SZ, 'REG_MULTI_SZ', "\c@\c@", ''],
        ['multi_sz6', REG_MULTI_SZ, 'REG_MULTI_SZ', "\c@", ''],
        ['multi_sz7', REG_MULTI_SZ, 'REG_MULTI_SZ', "", '(no data)'],
        ['', REG_SZ, 'REG_SZ', 'www.perl.com', 'www.perl.com'],
        ['0', REG_SZ, 'REG_SZ', 'www.perl.com', 'www.perl.com'],
    );
    run_value_tests($key1, @tests);
}

{
    my $filename = find_file('winnt_value_tests.rf');

    my $registry = Parse::Win32Registry->new($filename);
    isa_ok($registry, 'Parse::Win32Registry::WinNT::File');

    my $root_key = $registry->get_root_key;
    isa_ok($root_key, 'Parse::Win32Registry::WinNT::Key');
    is($root_key->get_name, '$$$PROTO.HIV', 'Root Key name');

    my $key1 = $root_key->get_subkey('key1');
    ok(defined($key1), 'key1 defined');
    is($key1->get_name, 'key1', 'key1 name');

    my @tests = (
        ['sz1', REG_SZ, 'REG_SZ', 'www.perl.com', 'www.perl.com'],
        ['sz2', REG_SZ, 'REG_SZ', 'www.perl.com', 'www.perl.com'],
        ['sz3', REG_SZ, 'REG_SZ', '12', '12'],
        ['sz4', REG_SZ, 'REG_SZ', '1', '1'],
        ['sz5', REG_SZ, 'REG_SZ', '', '(no data)'],
        ['sz6', REG_SZ, 'REG_SZ', '', '(no data)'],
        ['sz7', REG_SZ, 'REG_SZ', '', '(no data)'],
        ['sz8', REG_SZ, 'REG_SZ', '', '(no data)'],
        #['sz9', REG_SZ, 'REG_SZ', '', '(no data)'],
        ['expand_sz1', REG_EXPAND_SZ, 'REG_EXPAND_SZ', 'www.perl.com', 'www.perl.com'],
        ['expand_sz2', REG_EXPAND_SZ, 'REG_EXPAND_SZ', 'www.perl.com', 'www.perl.com'],
        ['expand_sz3', REG_EXPAND_SZ, 'REG_EXPAND_SZ', '12', '12'],
        ['expand_sz4', REG_EXPAND_SZ, 'REG_EXPAND_SZ', '1', '1'],
        ['expand_sz5', REG_EXPAND_SZ, 'REG_EXPAND_SZ', '', '(no data)'],
        ['expand_sz6', REG_EXPAND_SZ, 'REG_EXPAND_SZ', '', '(no data)'],
        ['expand_sz7', REG_EXPAND_SZ, 'REG_EXPAND_SZ', '', '(no data)'],
        ['expand_sz8', REG_EXPAND_SZ, 'REG_EXPAND_SZ', '', '(no data)'],
        ['binary1', REG_BINARY, 'REG_BINARY', "\x01\x02\x03\x04\x05\x06\x07\x08", '01 02 03 04 05 06 07 08'],
        ['binary2', REG_BINARY, 'REG_BINARY', '', '(no data)'],
        ['dword1', REG_DWORD, 'REG_DWORD', 1, '0x00000001 (1)'],
        ['dword3', REG_DWORD, 'REG_DWORD', undef, '(invalid data)'],
        ['dword4', REG_DWORD, 'REG_DWORD', undef, '(invalid data)'],
        ['dword5', REG_DWORD, 'REG_DWORD', 0x04030201, '0x04030201 (67305985)'],
        ['dword6', REG_DWORD, 'REG_DWORD', undef, '(invalid data)'],
        ['dword7', REG_DWORD, 'REG_DWORD', undef, '(invalid data)'],
        ['dword8', REG_DWORD, 'REG_DWORD', undef, '(invalid data)'],
        ['dword9', REG_DWORD, 'REG_DWORD', 0, '0x00000000 (0)'],
        ['dword10', REG_DWORD, 'REG_DWORD', 0x7fffffff, '0x7fffffff (2147483647)'],
        ['dword11', REG_DWORD, 'REG_DWORD', 0x80000000, '0x80000000 (2147483648)'],
        ['dword12', REG_DWORD, 'REG_DWORD', 0xffffffff, '0xffffffff (4294967295)'],
        ['multi_sz1', REG_MULTI_SZ, 'REG_MULTI_SZ', "String1\c@String2\c@String3\c@\c@", '[0] String1 [1] String2 [2] String3'],
        ['multi_sz2', REG_MULTI_SZ, 'REG_MULTI_SZ', "String1\c@\c@", '[0] String1'],
        ['multi_sz3', REG_MULTI_SZ, 'REG_MULTI_SZ', "String1\c@", '[0] String1'],
        ['multi_sz4', REG_MULTI_SZ, 'REG_MULTI_SZ', "String1", '[0] String1'],
        ['multi_sz5', REG_MULTI_SZ, 'REG_MULTI_SZ', "\c@\c@", ''],
        ['multi_sz6', REG_MULTI_SZ, 'REG_MULTI_SZ', "\c@", ''],
        ['multi_sz7', REG_MULTI_SZ, 'REG_MULTI_SZ', "", '(no data)'],
        ['', REG_SZ, 'REG_SZ', 'www.perl.com', 'www.perl.com'],
        ['0', REG_SZ, 'REG_SZ', 'www.perl.com', 'www.perl.com'],
    );
    run_value_tests($key1, @tests);
}
