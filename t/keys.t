use strict;
use warnings;

use Test::More 'no_plan';

use Parse::Win32Registry qw(:REG_); # :REG_ constants are tested elsewhere

die 'Incorrect version' if $Parse::Win32Registry::VERSION != '0.30';

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
        ok(defined($key), 'key defined');
        is($key->get_name, $name, "get_name eq '$name'");
        
        is($key->get_path, "$root_key_name\\$path",
            "get_path eq '$root_key_name\\$path'");

        my @subkeys = $key->get_list_of_subkeys;
        is(@subkeys, $num_subkeys, "has $num_subkeys subkeys");

        my @values = $key->get_list_of_values;
        is(@values, $num_values, "has $num_values values");
        
        if (defined($timestamp)) {
            cmp_ok($key->get_timestamp, '==', $timestamp,
                "get_timestamp == $timestamp"
            );
        }
        else {
            ok(!defined($key->get_timestamp), 'get_timestamp undefined');
        }

        is($key->get_timestamp_as_string,
            $timestamp_as_string,
            "get_timestamp_as_string eq '$timestamp_as_string'"
        );

        my $as_string = defined($timestamp)
                      ? "$root_key_name\\$path [$timestamp_as_string]"
                      : "$root_key_name\\$path";
        is($key->as_string, $as_string, "as_string eq '$as_string'");
    }
}

{
    my $filename = find_file('win95_key_tests.rf');

    my $registry = Parse::Win32Registry->new($filename);
    ok(defined($registry), 'registry defined');
    isa_ok($registry, 'Parse::Win32Registry::Win95::File');

    my $root_key = $registry->get_root_key;
    ok(defined($registry), 'root key defined');
    isa_ok($root_key, 'Parse::Win32Registry::Win95::Key');
    is($root_key->get_name, '', 'root key name');
    is($root_key->get_path, '', 'root key path');
    my @subkeys = $root_key->get_list_of_subkeys;
    is(@subkeys, 3, 'root key has 3 subkeys');

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
        ['',           '',     1, 0, undef, '(undefined)'],
        ['\\0',        '0',    0, 0, undef, '(undefined)'],
    );
    run_key_tests($root_key, @tests);
}

{
    my $filename = find_file('winnt_key_tests.rf');

    my $registry = Parse::Win32Registry->new($filename);
    ok(defined($registry), 'registry defined');
    isa_ok($registry, 'Parse::Win32Registry::WinNT::File');

    my $root_key = $registry->get_root_key;
    ok(defined($registry), 'root key defined');
    isa_ok($root_key, 'Parse::Win32Registry::WinNT::Key');
    is($root_key->get_name, '$$$PROTO.HIV', 'root key name');
    is($root_key->get_path, '$$$PROTO.HIV', 'root key path');
    my @subkeys = $root_key->get_list_of_subkeys;
    is(@subkeys, 3, 'root key has 3 subkeys');

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
        ['',           '',     1, 0, 1303375328, '2011-04-21T08:42:08Z'],
        ['\\0',        '0',    0, 0, 1331522826, '2012-03-12T03:27:06Z'],
    );
    run_key_tests($root_key, @tests);
}

