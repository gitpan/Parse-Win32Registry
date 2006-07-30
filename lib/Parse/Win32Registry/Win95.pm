package Parse::Win32Registry::Win95;

use strict;
use warnings;

use Parse::Win32Registry::Win95::Key;

use Carp;

sub new {
    my $class = shift; 
    my $filename = shift;

    open my $regfile, "<", $filename or croak "Unable to open $filename: $!";

    # CREG Header
    # 0x00 dword = 'CREG' signature
    # 0x04 dword = some kind of version?
    # 0x08 dword = offset to first rgdb block
    # 0x0c
    # 0x10 word  = number of rgdb blocks

    sysread($regfile, my $creg_header, 32);
    if (!defined($creg_header) || length($creg_header) != 32) {
        croak "Could not read registry file header\n";
    }

    my $creg_sig = unpack("a4", $creg_header);
    if ($creg_sig ne "CREG") {
        croak "Invalid registry file signature\n";
    }

    # RGKN Block Header
    # 0x0 dword = 'RGKN' signature
    # 0x4 dword = size of RGKN block
    # 0x8 dword = offset to root key entry (relative to start of RGKN)

    sysseek($regfile, 0x20, 0);
    sysread($regfile, my $rgkn_header, 32);
    if (!defined($rgkn_header) || length($rgkn_header) != 32) {
        croak "Could not read RGKN header at offset 0x20\n";
    }
    
    my ($rgkn_sig, $rgkn_block_size, $offset_to_root_key)
        = unpack("a4VV", $rgkn_header);
    if ($rgkn_sig ne "RGKN") {
        croak "Invalid RGKN block signature at offset 0x20\n";
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
