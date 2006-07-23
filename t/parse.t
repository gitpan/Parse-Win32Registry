# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Parse-Win32Registry.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

#use Test::More 'no_plan';
use Test::More tests => 29;
BEGIN { use_ok('Parse::Win32Registry') };

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.

use strict;
use warnings;

use constant REG_DWORD => 4;
use constant REG_BINARY => 3;
use constant REG_SZ => 1;

{
    my $registry = Parse::Win32Registry->new('t/test1.dat');
    isa_ok($registry, 'Parse::Win32Registry::Win95');

    my $root_key = $registry->get_root_key;
    isa_ok($root_key, 'Parse::Win32Registry::Win95::Key');
    is($root_key->get_name, '', 'Root Key name');

    my $testkey1 = $root_key->get_subkey('TestKey1');
    is($testkey1->get_name, 'TestKey1', 'TestKey1 name');

    my $value1 = $testkey1->get_value('Value1');
    isa_ok($value1, 'Parse::Win32Registry::Win95::Value');
    is($value1->get_name, 'Value1', 'Value1 name');
    is($value1->get_type, REG_DWORD, 'Value1 type');
    is($value1->get_data, 10, 'Value1 data');

    my $value2 = $testkey1->get_value('Value2');
    is($value2->get_name, 'Value2', 'Value2 name');
    is($value2->get_type, REG_BINARY, 'Value2 type');
    is($value2->get_data, "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a", 'Value2 data');

    my $value3 = $testkey1->get_value('Value3');
    is($value3->get_name, 'Value3', 'Value3 name');
    is($value3->get_type, REG_SZ, 'Value3 type');
    is($value3->get_data, 'http://www.msn.com', 'Value3 data');
}

{
    my $registry = Parse::Win32Registry->new('t/test2.dat');
    isa_ok($registry, 'Parse::Win32Registry::WinNT');

    my $root_key = $registry->get_root_key;
    isa_ok($root_key, 'Parse::Win32Registry::WinNT::Key');
    is($root_key->get_name, '$$$PROTO.HIV', 'Root Key name');

    my $testkey1 = $root_key->get_subkey('TestKey1');
    is($testkey1->get_name, 'TestKey1', 'TestKey1 name');

    my $value1 = $testkey1->get_value('Value1');
    isa_ok($value1, 'Parse::Win32Registry::WinNT::Value');
    is($value1->get_name, 'Value1', 'Value1 name');
    is($value1->get_type, REG_BINARY, 'Value1 type');
    is($value1->get_data, "\x01\x02\x03\x04\x05\x06\x07\x08\x01\x02\x03\x04\x05\x06\x07\x08", 'Value1 data');

    my $value2 = $testkey1->get_value('Value2');
    is($value2->get_name, 'Value2', 'Value2 name');
    is($value2->get_type, REG_SZ, 'Value2 type');
    is($value2->get_data, 'C:\Documents and Settings\Administrator\My Documents', 'Value2 data');

    my $value3 = $testkey1->get_value('Value3');
    is($value3->get_name, 'Value3', 'Value3 name');
    is($value3->get_type, REG_DWORD, 'Value3 type');
    is($value3->get_data, 6, 'Value3 data');
}


