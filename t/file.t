use strict;
use warnings;

use Test::More 'no_plan';
use Parse::Win32Registry 0.50;

sub find_file
{
    my $filename = shift;
    return -d 't' ? "t/$filename" : $filename;
}

{
    my $filename = find_file('win95_key_tests.rf');

    my $registry = Parse::Win32Registry->new($filename);
    ok(defined($registry), 'registry defined');
    isa_ok($registry, 'Parse::Win32Registry::Win95::File');

    my $timestamp_as_string = '(undefined)';

    my $desc = "95";

    is($registry->get_filename, $filename,
        "$desc get_filename eq '$filename'");
    ok(!defined($registry->get_timestamp),
        "$desc get_timestamp undefined");
    is($registry->get_timestamp_as_string, $timestamp_as_string,
        "$desc get_timestamp_as_string eq '$timestamp_as_string'");
    ok(!defined($registry->get_embedded_filename),
        "$desc get_embedded_filename undefined");
}

{
    my $filename = find_file('winnt_key_tests.rf');

    my $registry = Parse::Win32Registry->new($filename);
    ok(defined($registry), 'registry defined');
    isa_ok($registry, 'Parse::Win32Registry::WinNT::File');

    my $timestamp = 1162637840;
    my $timestamp_as_string = '2006-11-04T10:57:20Z';
    my $embedded_filename = 'ttings\Administrator\ntuser.dat';

    my $desc = "NT";

    is($registry->get_filename, $filename,
        "$desc get_filename eq '$filename'");
    cmp_ok($registry->get_timestamp, '==', $timestamp,
        "$desc get_timestamp == $timestamp");
    is($registry->get_timestamp_as_string, $timestamp_as_string,
        "$desc get_timestamp_as_string eq '$timestamp_as_string'");
    is($registry->get_embedded_filename, $embedded_filename,
        "$desc get_embedded_filename eq '$embedded_filename'");
}
