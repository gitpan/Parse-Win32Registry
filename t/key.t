use strict;
use warnings;

use Test::More 'no_plan';
use Parse::Win32Registry;

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
        my $path = $test->{path};
        my $name = $test->{name};
        my $num_subkeys = $test->{num_subkeys};
        my $num_values = $test->{num_values};
        my $timestamp = $test->{timestamp};
        my $timestamp_as_string = $test->{timestamp_as_string};
        my $type = $test->{type};
        my $class_name = $test->{class_name};

        my $key_path = "$root_key_name\\$path";

        my $key = $root_key->get_subkey($path);
        ok(defined($key), 'key defined');
        ok(!$key->is_root, 'key is not root');
        is($key->get_name, $name, "get_name eq '$name'");
        is($key->get_path, $key_path, "get_path eq '$key_path'");

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

        if (defined($type)) {
            is($key->get_type, $type, "get_type");
        }
        else {
            ok(!defined($key->get_type), 'get_type undefined');
        }

        if (defined($class_name)) {
            is($key->get_class_name, $class_name, "get_class_name");
        }
        else {
            ok(!defined($key->get_class_name), 'get_class_name undefined');
        }

        my $as_string = defined($timestamp)
                      ? "$key_path [$timestamp_as_string]"
                      : "$key_path";
        is($key->as_string, $as_string, "as_string eq '$as_string'");

        is($key->as_regedit_export, "[$key_path]\n", 'as_regedit_export');

        # parent key tests
        my $parent_key = $key->get_parent;
        ok(defined($parent_key), 'parent key defined');

        # $parent_key->get_subkey should be the same as key
        my $clone_key = $parent_key->get_subkey($name);
        ok(defined($clone_key), "parent subkey defined");
        is($clone_key->get_path, "$key_path", "get_path eq '$key_path'");
        is($clone_key->get_timestamp_as_string,
            $timestamp_as_string,
            "get_timestamp_as_string eq '$timestamp_as_string'"
        );

        is($key->regenerate_path, $key_path, "regenerate_path");
        is($key->get_path, $key_path, "get_path after regenerate_path");
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
    ok($root_key->is_root, 'root key is root');
    ok(!defined($root_key->get_type), 'root key get_type undefined');
    is($root_key->get_name, '', 'root key name');
    is($root_key->get_path, '', 'root key path');
    is($root_key->as_regedit_export, "[]\n", 'root key as_regedit_export');
    my @subkeys = $root_key->get_list_of_subkeys;
    is(@subkeys, 3, 'root key has 3 subkeys');

    my @tests = (
        {
            path => 'key1',
            name => 'key1',
            num_subkeys => 3,
            num_values => 0,
            timestamp => undef,
            timestamp_as_string => '(undefined)',
        },
        {
            path => 'key2',
            name => 'key2',
            num_subkeys => 6,
            num_values => 0,
            timestamp => undef,
            timestamp_as_string => '(undefined)',
        },
        {
            path => 'key1\\key3',
            name => 'key3',
            num_subkeys => 0,
            num_values => 0,
            timestamp => undef,
            timestamp_as_string => '(undefined)',
        },
        {
            path => 'key1\\key4',
            name => 'key4',
            num_subkeys => 0,
            num_values => 0,
            timestamp => undef,
            timestamp_as_string => '(undefined)',
        },
        {
            path => 'key1\\key5',
            name => 'key5',
            num_subkeys => 0,
            num_values => 0,
            timestamp => undef,
            timestamp_as_string => '(undefined)',
        },
        {
            path => 'key2\\key6',
            name => 'key6',
            num_subkeys => 0,
            num_values => 0,
            timestamp => undef,
            timestamp_as_string => '(undefined)',
        },
        {
            path => 'key2\\key7',
            name => 'key7',
            num_subkeys => 0,
            num_values => 0,
            timestamp => undef,
            timestamp_as_string => '(undefined)',
        },
        {
            path => 'key2\\key8',
            name => 'key8',
            num_subkeys => 0,
            num_values => 0,
            timestamp => undef,
            timestamp_as_string => '(undefined)',
        },
        {
            path => 'key2\\key9',
            name => 'key9',
            num_subkeys => 0,
            num_values => 0,
            timestamp => undef,
            timestamp_as_string => '(undefined)',
        },
        {
            path => 'key2\\key10',
            name => 'key10',
            num_subkeys => 0,
            num_values => 0,
            timestamp => undef,
            timestamp_as_string => '(undefined)',
        },
        {
            path => 'key2\\key11',
            name => 'key11',
            num_subkeys => 0,
            num_values => 0,
            timestamp => undef,
            timestamp_as_string => '(undefined)',
        },
        {
            path => '',
            name => '',
            num_subkeys => 1,
            num_values => 0,
            timestamp => undef,
            timestamp_as_string => '(undefined)',
        },
        {
            path => '\\0',
            name => '0',
            num_subkeys => 0,
            num_values => 0,
            timestamp => undef,
            timestamp_as_string => '(undefined)',
        },
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
    ok($root_key->is_root, 'root key is_root');
    is($root_key->get_type, 0x2c, 'root key get_type');
    is($root_key->get_name, '$$$PROTO.HIV', 'root key name');
    is($root_key->get_path, '$$$PROTO.HIV', 'root key path');
    is($root_key->as_regedit_export, "[\$\$\$PROTO.HIV]\n",
        'root key as_regedit_export');
    my @subkeys = $root_key->get_list_of_subkeys;
    is(@subkeys, 3, 'root key has 3 subkeys');

    my @tests = (
        {
            path => 'key1',
            name => 'key1',
            num_subkeys => 3,
            num_values => 0,
            timestamp => 993752854,
            timestamp_as_string => '2001-06-28T18:27:34Z',
            type => 0x20,
            class_name => 'Class',
        },
        {
            path => 'key2',
            name => 'key2',
            num_subkeys => 6,
            num_values => 0,
            timestamp => 1021900351,
            timestamp_as_string => '2002-05-20T13:12:31Z',
            type => 0x20,
            class_name => 'Class',
        },
        {
            path => 'key1\\key3',
            name => 'key3',
            num_subkeys => 0,
            num_values => 0,
            timestamp => 1050047849,
            timestamp_as_string => '2003-04-11T07:57:29Z',
            type => 0x20,
        },
        {
            path => 'key1\\key4',
            name => 'key4',
            num_subkeys => 0,
            num_values => 0,
            timestamp => 1078195347,
            timestamp_as_string => '2004-03-02T02:42:27Z',
            type => 0x20,
        },
        {
            path => 'key1\\key5',
            name => 'key5',
            num_subkeys => 0,
            num_values => 0,
            timestamp => 1106342844,
            timestamp_as_string => '2005-01-21T21:27:24Z',
            type => 0x20,
        },
        {
            path => 'key2\\key6',
            name => 'key6',
            num_subkeys => 0,
            num_values => 0,
            timestamp => 1134490342,
            timestamp_as_string => '2005-12-13T16:12:22Z',
            type => 0x20,
        },
        {
            path => 'key2\\key7',
            name => 'key7',
            num_subkeys => 0,
            num_values => 0,
            timestamp => 1162637840,
            timestamp_as_string => '2006-11-04T10:57:20Z',
            type => 0x20,
        },
        {
            path => 'key2\\key8',
            name => 'key8',
            num_subkeys => 0,
            num_values => 0,
            timestamp => 1190785338,
            timestamp_as_string => '2007-09-26T05:42:18Z',
            type => 0x20,
        },
        {
            path => 'key2\\key9',
            name => 'key9',
            num_subkeys => 0,
            num_values => 0,
            timestamp => 1218932835,
            timestamp_as_string => '2008-08-17T00:27:15Z',
            type => 0x20,
        },
        {
            path => 'key2\\key10',
            name => 'key10',
            num_subkeys => 0,
            num_values => 0,
            timestamp => 1247080333,
            timestamp_as_string => '2009-07-08T19:12:13Z',
            type => 0x20,
        },
        {
            path => 'key2\\key11',
            name => 'key11',
            num_subkeys => 0,
            num_values => 0,
            timestamp => 1275227831,
            timestamp_as_string => '2010-05-30T13:57:11Z',
            type => 0x20,
        },
        {
            path => '',
            name => '',
            num_subkeys => 1,
            num_values => 0,
            timestamp => 1303375328,
            timestamp_as_string => '2011-04-21T08:42:08Z',
            type => 0x20,
        },
        {
            path => '\\0',
            name => '0',
            num_subkeys => 0,
            num_values => 0,
            timestamp => 1331522826,
            timestamp_as_string => '2012-03-12T03:27:06Z',
            type => 0x20,
        },
    );
    run_key_tests($root_key, @tests);
}
