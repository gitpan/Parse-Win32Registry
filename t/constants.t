use strict;
use warnings;

use Test::More 'no_plan';
#use Test::More tests => 100;

use Parse::Win32Registry qw(:REG_);

die "Incorrect version" if $Parse::Win32Registry::VERSION != '0.25';

sub find_file
{
    my $filename = shift;
    return -d 't' ? "t/$filename" : $filename;
}

{
    my @tests = (
        ['REG_NONE' => 0],
        ['REG_SZ' => 1],
        ['REG_EXPAND_SZ' => 2],
        ['REG_BINARY' => 3],
        ['REG_DWORD' => 4],
        ['REG_DWORD_BIG_ENDIAN' => 5],
        ['REG_LINK' => 6],
        ['REG_MULTI_SZ' => 7],
        ['REG_RESOURCE_LIST' => 8],
        ['REG_FULL_RESOURCE_DESCRIPTOR' => 9],
        ['REG_RESOURCE_REQUIREMENTS_LIST' => 10],
        ['REG_QWORD' => 11],
    );

    foreach my $test (@tests) {
        my ($name, $constant) = @{ $test };
        cmp_ok(eval $name, '==', $constant, "$name == $constant");
    }
}
