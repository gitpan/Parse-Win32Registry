use strict;
use warnings;

use Test::More 'no_plan';
#use Test::More tests => 100;

use Parse::Win32Registry qw(:REG_);

die "Incorrect version" if $Parse::Win32Registry::VERSION != '0.24';

sub find_file
{
    my $filename = shift;
    return -d 't' ? "t/$filename" : $filename;
}

sub run_key_tests
{
    my $root_key = shift;
    my @tests = @_;

    my $root_key_name = $root_key->get_name; # should already be tested

    foreach my $test (@tests) {
        my ($path,
            $name,
            $num_subkeys,
            $num_values,
            $timestamp, 
            $timestamp_as_string) = @$test;

        my $key = $root_key->get_subkey($path);
        ok(defined($key), "$name defined");
        is($key->get_name, $name, "$name name");
        
        is($key->get_path, "$root_key_name\\$path", "$name path");

        my @subkeys = $key->get_list_of_subkeys;
        is(@subkeys, $num_subkeys, "$name has $num_subkeys subkeys");
        my @values = $key->get_list_of_values;
        is(@values, $num_values, "$name has $num_values values");
        
        if (defined($timestamp)) {
            cmp_ok($key->get_timestamp, '==', $timestamp,
                "$name timestamp == $timestamp"
            );
        }
        else {
            ok(!defined($key->get_timestamp), "$name timestamp undefined");
        }
        is($key->get_timestamp_as_string,
            $timestamp_as_string,
            "$name timestamp_as_string eq '$timestamp_as_string'"
        );
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
    is($root_key->get_path, '', 'root key path');

    my @tests = (
        ['key1',       'key1', 3, 0, undef, '(undefined)'],
        ['key2',       'key2', 6, 0, undef, '(undefined)'],
        ['key1\\key1', 'key1', 0, 0, undef, '(undefined)'],
        ['key1\\key2', 'key2', 0, 0, undef, '(undefined)'],
        ['key1\\key3', 'key3', 0, 0, undef, '(undefined)'],
        ['key2\\key1', 'key1', 0, 0, undef, '(undefined)'],
        ['key2\\key2', 'key2', 0, 0, undef, '(undefined)'],
        ['key2\\key3', 'key3', 0, 0, undef, '(undefined)'],
        ['key2\\key4', 'key4', 0, 0, undef, '(undefined)'],
        ['key2\\key5', 'key5', 0, 0, undef, '(undefined)'],
        ['key2\\key6', 'key6', 0, 0, undef, '(undefined)'],
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
    is($root_key->get_path, '$$$PROTO.HIV', 'root key path');

    my @tests = (
        ['key1',       'key1', 3, 0, 993752854,  '2001-06-28T18:27:34Z'],
        ['key2',       'key2', 6, 0, 1021900351, '2002-05-20T13:12:31Z'],
        ['key1\\key1', 'key1', 0, 0, 1050047849, '2003-04-11T07:57:29Z'],
        ['key1\\key2', 'key2', 0, 0, 1078195347, '2004-03-02T02:42:27Z'],
        ['key1\\key3', 'key3', 0, 0, 1106342844, '2005-01-21T21:27:24Z'],
        ['key2\\key1', 'key1', 0, 0, 1134490342, '2005-12-13T16:12:22Z'],
        ['key2\\key2', 'key2', 0, 0, 1162637840, '2006-11-04T10:57:20Z'],
        ['key2\\key3', 'key3', 0, 0, 1190785338, '2007-09-26T05:42:18Z'],
        ['key2\\key4', 'key4', 0, 0, 1218932835, '2008-08-17T00:27:15Z'],
        ['key2\\key5', 'key5', 0, 0, 1247080333, '2009-07-08T19:12:13Z'],
        ['key2\\key6', 'key6', 0, 0, 1275227831, '2010-05-30T13:57:11Z'],
    );
    run_key_tests($root_key, @tests);
}

