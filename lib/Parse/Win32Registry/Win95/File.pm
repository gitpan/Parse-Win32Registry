package Parse::Win32Registry::Win95::File;

use strict;
use warnings;

use base qw(Parse::Win32Registry::File);

use Carp;
use File::Basename;
use Parse::Win32Registry::Base qw(:all);
use Parse::Win32Registry::Win95::Key;
use Parse::Win32Registry::Win95::Entry;

use constant OFFSET_TO_RGKN_BLOCK => 0x20;
use constant RGKN_ENTRY_SIZE => 28;

sub new {
    my $class = shift; 
    my $filename = shift or croak "No filename specified";

    open my $regfile, "<", $filename or croak "Unable to open '$filename': $!";

    # CREG Header
    # 0x00 dword = 'CREG' signature
    # 0x04 dword = some kind of version?
    # 0x08 dword = offset to first rgdb block
    # 0x0c
    # 0x10 word  = number of rgdb blocks

    sysread($regfile, my $creg_header, 32);
    if (!defined($creg_header) || length($creg_header) != 32) {
        log_error("Could not read registry file header");
        return;
    }

    my $creg_sig = unpack("a4", $creg_header);
    if ($creg_sig ne "CREG") {
        log_error("Invalid registry file signature");
        return;
    }

    # RGKN Block Header
    # 0x0 dword = 'RGKN' signature
    # 0x4 dword = size of RGKN block
    # 0x8 dword = offset to root key entry (relative to start of RGKN)

    sysseek($regfile, OFFSET_TO_RGKN_BLOCK, 0);
    sysread($regfile, my $rgkn_header, 32);
    if (!defined($rgkn_header) || length($rgkn_header) != 32) {
        log_error("Could not read RGKN header at 0x%x", OFFSET_TO_RGKN_BLOCK);
        return;
    }
    
    my ($rgkn_sig,
        $rgkn_block_size,
        $offset_to_root_key) = unpack("a4VV", $rgkn_header);

    if ($rgkn_sig ne "RGKN") {
        log_error("Invalid RGKN block signature at 0x%x", OFFSET_TO_RGKN_BLOCK);
        return;
    }

    $offset_to_root_key += OFFSET_TO_RGKN_BLOCK;

    my $self = {};
    $self->{_regfile} = $regfile;
    $self->{_offset_to_root_key} = $offset_to_root_key;
    $self->{_filename} = $filename;
    bless $self, $class;

    return $self;
}

sub get_root_key {
    my $self = shift;

    my $regfile = $self->{_regfile};
    my $offset_to_root_key = $self->{_offset_to_root_key};

    my $root_key = Parse::Win32Registry::Win95::Key->new($regfile,
                                                         $offset_to_root_key,
                                                         undef);
    return $root_key;
}

sub get_virtual_root_key {
    my $self = shift;
    my $fake_root = shift;

    my $root_key = $self->get_root_key;

    if (!defined $fake_root) {
        # guess virtual root from filename
        my $filename = basename $self->{_filename};

        if ($filename =~ /USER/i) {
            $fake_root = 'HKEY_USERS';
        }
        elsif ($filename =~ /SYSTEM/i) {
            $fake_root = 'HKEY_LOCAL_MACHINE';
        }
        else {
            $fake_root = 'HKEY_UNKNOWN';
        }
    }

    $root_key->{_name} = $fake_root;
    $root_key->{_key_path} = $fake_root;

    return $root_key;
}

sub get_timestamp {
    return undef;
}

sub get_timestamp_as_string {
    return iso8601(undef);
}

sub get_embedded_filename {
    return undef
}

sub get_next_entry {
    my $self = shift;

    my $regfile = $self->{_regfile};
    my $offset = $self->{_offset_to_next_entry};

    if (!defined $offset) {
        $self->move_to_first_entry;
        $offset = $self->{_offset_to_next_entry};
    }

    my $rgkn_block_size = $self->{_rgkn_block_size};

    if ($self->{_end_of_data}) {
        return;
    }

    if ($offset >= OFFSET_TO_RGKN_BLOCK + $rgkn_block_size) {
        $self->{_end_of_data} = 1;
        return;
    }

    if (my $entry = Parse::Win32Registry::Win95::Entry->new($regfile,
                                                            $offset)) {
        # rgkn entry size is fixed
        $self->{_offset_to_next_entry} = $offset + 28;
        return $entry;
    }
    else {
        $self->{_end_of_data} = 1;
        return;
    }
}

sub move_to_first_entry {
    my $self = shift;

    my $regfile = $self->{_regfile};

    sysseek($regfile, OFFSET_TO_RGKN_BLOCK, 0);
    sysread($regfile, my $rgkn_header, 0x20);
    if (!defined($rgkn_header) || length($rgkn_header) != 0x20) {
        $self->{_end_of_data} = 1;
        return;
    }

    my ($rgkn_sig,
        $rgkn_block_size,
        $offset_to_root_key) = unpack("a4VV", $rgkn_header);

    my $offset = OFFSET_TO_RGKN_BLOCK + $offset_to_root_key;

    $self->{_end_of_data} = 0;
    $self->{_rgkn_block_size} = $rgkn_block_size;
    $self->{_offset_to_next_entry} = $offset;
}

1;
