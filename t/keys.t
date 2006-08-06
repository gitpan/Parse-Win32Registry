use strict;
use warnings;

use blib;

use Test::More 'no_plan';
#use Test::More tests => 100;

use Parse::Win32Registry qw(:REG_);

die "Incorrect version" if $Parse::Win32Registry::VERSION != '0.22';

sub find_file
{
    my $filename = shift;
    return -d 't' ? "t/$filename" : $filename;
}

sub run_key_tests
{
    my $root_key = shift;
    my @tests = @_;

    foreach my $test (@tests) {
        my ($path, $name, $num_subkeys, $num_values) = @$test;
        my $key = $root_key->get_subkey($path);
        ok(defined($key), "$name defined");
        is($key->get_name, $name, "$name name");
        my @subkeys = $key->get_list_of_subkeys;
        is(@subkeys, $num_subkeys, "$name has $num_subkeys subkeys");
        my @values = $key->get_list_of_values;
        is(@values, $num_values, "$name has $num_values values");
    }
}

{
    my $filename = find_file('win95_key_tests.rf');

    my $registry = Parse::Win32Registry->new($filename);
    ok(defined($registry), 'registry defined');
    isa_ok($registry, 'Parse::Win32Registry::Win95');

    my $root_key = $registry->get_root_key;
    ok(defined($registry), 'root key defined');
    isa_ok($root_key, 'Parse::Win32Registry::Win95::Key');
    is($root_key->get_name, '', 'root key name');

    my @tests = (
        ['key1', 'key1', 3, 0],
        ['key2', 'key2', 6, 0],
        ['key1\\key1', 'key1', 0, 0],
        ['key1\\key2', 'key2', 0, 0],
        ['key1\\key3', 'key3', 0, 0],
        ['key2\\key1', 'key1', 0, 0],
        ['key2\\key2', 'key2', 0, 0],
        ['key2\\key3', 'key3', 0, 0],
        ['key2\\key4', 'key4', 0, 0],
        ['key2\\key5', 'key5', 0, 0],
        ['key2\\key6', 'key6', 0, 0],
    );
    run_key_tests($root_key, @tests);
}

{
    my $filename = find_file('winnt_key_tests.rf');

    my $registry = Parse::Win32Registry->new($filename);
    ok(defined($registry), 'registry defined');
    isa_ok($registry, 'Parse::Win32Registry::WinNT');

    my $root_key = $registry->get_root_key;
    ok(defined($registry), 'root key defined');
    isa_ok($root_key, 'Parse::Win32Registry::WinNT::Key');
    is($root_key->get_name, '$$$PROTO.HIV', 'root key name');

    my @tests = (
        ['key1', 'key1', 3, 0],
        ['key2', 'key2', 6, 0],
        ['key1\\key1', 'key1', 0, 0],
        ['key1\\key2', 'key2', 0, 0],
        ['key1\\key3', 'key3', 0, 0],
        ['key2\\key1', 'key1', 0, 0],
        ['key2\\key2', 'key2', 0, 0],
        ['key2\\key3', 'key3', 0, 0],
        ['key2\\key4', 'key4', 0, 0],
        ['key2\\key5', 'key5', 0, 0],
        ['key2\\key6', 'key6', 0, 0],
    );
    run_key_tests($root_key, @tests);
}

