use strict;
use warnings;

use Test::More 'no_plan';
use Parse::Win32Registry 0.50;

sub find_file
{
    my $filename = shift;
    return -d 't' ? "t/$filename" : $filename;
}

sub run_entry_tests
{
    my $registry = shift;
    my @tests = @_;

    my ($os) = ref($registry) =~ /Win(NT|95)/;

    foreach my $loop (1..2) {
        $registry->move_to_first_entry if $loop > 1; # check reset works
        my $entry_num = 0;
        foreach my $test (@tests) {
            my $offset = $test->{offset};
            my $length = $test->{length};
            my $tag = $test->{tag};
            my $allocated = $test->{allocated};
            $entry_num++;

            my $desc = sprintf "(pass $loop) $os entry at 0x%x", $offset;

            my $entry = $registry->get_next_entry;

            ok(defined($entry), "$desc defined (valid entry)");
            is($entry->get_offset, $offset, "$desc get_offset");
            is($entry->get_length, $length, "$desc get_length");
            is($entry->get_tag, $tag, "$desc get_tag");
            is($entry->is_allocated, $allocated, "$desc is_allocated");
        }

        # check iterator is empty
        my $entry = $registry->get_next_entry;
        my $desc = "(pass $loop) $os";
        ok(!defined $entry, "$desc entry undefined (iterator finished)");
    }
}

{
    my $filename = find_file('win95_key_tests.rf');

    my $registry = Parse::Win32Registry->new($filename);
    ok(defined($registry), 'registry defined');
    isa_ok($registry, 'Parse::Win32Registry::Win95::File');

    my @tests = (
        {
            offset => 0x40,
        },
        {
            offset => 0x5c,
        },
        {
            offset => 0x78,
        },
        {
            offset => 0x94,
        },
        {
            offset => 0xb0,
        },
        {
            offset => 0xcc,
        },
        {
            offset => 0xe8,
        },
        {
            offset => 0x104,
        },
        {
            offset => 0x120,
        },
        {
            offset => 0x13c,
        },
        {
            offset => 0x158,
        },
        {
            offset => 0x174,
        },
        {
            offset => 0x190,
        },
        {
            offset => 0x1ac,
        },
    );
    foreach my $test (@tests) {
        $test->{length} = 28;
        $test->{tag} = 'rgkn';
        $test->{allocated} = 0;
    }
    run_entry_tests($registry, @tests);
}

{
    my $filename = find_file('winnt_key_tests.rf');

    my $registry = Parse::Win32Registry->new($filename);
    ok(defined($registry), 'registry defined');
    isa_ok($registry, 'Parse::Win32Registry::WinNT::File');

    my @tests = (
        {
            offset => 0x1020,
            length => 96,
            tag => "nk",
        },
        {
            offset => 0x1080,
            length => 88,
            tag => "nk",
        },
        {
            offset => 0x10d8,
            length => 16,
            tag => "",
        },
        {
            offset => 0x10e8,
            length => 88,
            tag => "nk",
        },
        {
            offset => 0x1140,
            length => 16,
            tag => "",
        },
        {
            offset => 0x1150,
            length => 80,
            tag => "nk",
        },
        {
            offset => 0x11a0,
            length => 32,
            tag => "lf",
        },
        {
            offset => 0x11c0,
            length => 104,
            tag => "sk",
        },
        {
            offset => 0x1228,
            length => 88,
            tag => "nk",
        },
        {
            offset => 0x1280,
            length => 88,
            tag => "nk",
        },
        {
            offset => 0x12d8,
            length => 88,
            tag => "nk",
        },
        {
            offset => 0x1330,
            length => 32,
            tag => "lh",
        },
        {
            offset => 0x1350,
            length => 88,
            tag => "nk",
        },
        {
            offset => 0x13a8,
            length => 88,
            tag => "nk",
        },
        {
            offset => 0x1400,
            length => 88,
            tag => "nk",
        },
        {
            offset => 0x1458,
            length => 88,
            tag => "nk",
        },
        {
            offset => 0x14b0,
            length => 88,
            tag => "nk",
        },
        {
            offset => 0x1508,
            length => 88,
            tag => "nk",
        },
        {
            offset => 0x1560,
            length => 20,
            tag => "li",
        },
        {
            offset => 0x1574,
            length => 20,
            tag => "li",
        },
        {
            offset => 0x1588,
            length => 16,
            tag => "ri",
        },
        {
            offset => 0x1598,
            length => 88,
            tag => "nk",
        },
        {
            offset => 0x15f0,
            length => 16,
            tag => "lf",
        },
    );
    foreach my $test (@tests) {
        $test->{allocated} = 1;
    }
    run_entry_tests($registry, @tests);
}
