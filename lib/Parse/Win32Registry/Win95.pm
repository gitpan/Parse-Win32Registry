package Parse::Win32Registry::Win95;

use strict;
use warnings;

use Parse::Win32Registry::Win95::Key;

use Carp;

sub new {
    my $class = shift; 
    my $filename = shift;

    open my $regfile, $filename or croak "unable to open $filename: $!";

    # CREG Header
    # 0x00 dword = 'CREG' signature
    # 0x04 dword = some kind of version?
    # 0x08 dword = offset to first rgdb block
    # 0x0c
    # 0x10 word  = number of rgdb blocks

    sysread($regfile, my $creg_header, 0x20);
    my $creg_sig = unpack("a4", $creg_header);
    if ($creg_sig ne "CREG") {
        croak "invalid registry file signature [$creg_sig]";
    }

    # RGKN Block Header
    # 0x0 dword = 'RGKN' signature
    # 0x4 dword = size of RGKN block
    # 0x8 dword = offset to root key entry (relative to start of RGKN)

    sysseek($regfile, 0x20, 0);
    sysread($regfile, my $rgkn_header, 0x20);
    my ($rgkn_sig, $rgkn_block_size, $offset_to_root_key)
        = unpack("a4VV", $rgkn_header);
    if ($rgkn_sig ne "RGKN") {
        croak sprintf("invalid RGKN block signature [%s] at offset 0x%x",
            $rgkn_sig, 0x20);
    }

    my $self = {};

    $self->{_regfile} = $regfile;
    $self->{_offset_to_root_key} = $offset_to_root_key;

    bless $self, $class;

    return $self;
}

sub get_root_key {
    my $self = shift;

    my $regfile = $self->{_regfile};
    my $offset_to_root_key = $self->{_offset_to_root_key};

    my $root_key = Parse::Win32Registry::Win95::Key->new($regfile,
                                                         $offset_to_root_key);
    return $root_key;
}

1;
