package Parse::Win32Registry::WinNT::File;

use strict;
use warnings;

use base qw(Parse::Win32Registry::File);

use Carp;
use Encode;
use File::Basename;
use Parse::Win32Registry::Base qw(:all);
use Parse::Win32Registry::WinNT::Key;
use Parse::Win32Registry::WinNT::Value;
use Parse::Win32Registry::WinNT::Entry;

use constant OFFSET_TO_FIRST_HBIN => 0x1000;

sub new {
    my $class = shift;
    my $filename = shift or croak "No filename specified";

    open my $regfile, "<", $filename or croak "Unable to open '$filename': $!";

    sysread($regfile, my $regf_header, 0x70);
    if (!defined($regf_header) || length($regf_header) != 0x70) {
        log_error("Could not read registry file header");
        return;
    }

    my ($regf_sig, $timestamp) = unpack("a4x8a8", $regf_header);
    if ($regf_sig ne "regf") {
        log_error("Invalid registry file signature");
        return;
    }

    my $embedded_filename = substr($regf_header, 0x30, 0x40);
    $embedded_filename = unpack("Z*", decode("UCS-2LE", $embedded_filename));
    
    my $offset_to_first_key = unpack("x36 V", $regf_header);
    $offset_to_first_key += OFFSET_TO_FIRST_HBIN;

    my $self = {};
    $self->{_regfile} = $regfile;
    $self->{_offset_to_root_key} = $offset_to_first_key;
    $self->{_timestamp} = unpack_windows_time($timestamp);
    $self->{_filename} = $filename;
    $self->{_embedded_filename} = $embedded_filename;
    bless $self, $class;

    return $self;
}

sub get_root_key {
    my $self = shift;

    my $regfile = $self->{_regfile};
    my $offset_to_root_key = $self->{_offset_to_root_key};

    my $root_key = Parse::Win32Registry::WinNT::Key->new($regfile,
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

        if ($filename =~ /NTUSER/i) {
            $fake_root = 'HKEY_CURRENT_USER';
        }
        elsif ($filename =~ /USRCLASS/i) {
            $fake_root = 'HKEY_CLASSES_ROOT';
        }
        elsif ($filename =~ /SOFTWARE/i) {
            $fake_root = 'HKEY_LOCAL_MACHINE\SOFTWARE';
        }
        elsif ($filename =~ /SYSTEM/i) {
            $fake_root = 'HKEY_LOCAL_MACHINE\SYSTEM';
        }
        elsif ($filename =~ /SAM/i) {
            $fake_root = 'HKEY_LOCAL_MACHINE\SAM';
        }
        elsif ($filename =~ /SECURITY/i) {
            $fake_root = 'HKEY_LOCAL_MACHINE\SECURITY';
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
    my $self = shift;

    return $self->{_timestamp};
}

sub get_timestamp_as_string {
    my $self = shift;

    return iso8601($self->{_timestamp});
}

sub get_embedded_filename {
    my $self = shift;

    return $self->{_embedded_filename};
}

sub get_next_hbin_header {
    my $self = shift;
    my $regfile = $self->{_regfile};

    if ($self->{_end_of_data}) {
        return;
    }

    my $offset_to_prev_hbin = $self->{_offset_to_hbin};
    my $size_of_prev_hbin = $self->{_size_of_hbin};

    my $offset_to_hbin;

    if (!defined $offset_to_prev_hbin || !defined $size_of_prev_hbin) {
        $offset_to_hbin = OFFSET_TO_FIRST_HBIN;
    }
    else {
        # jump to start of next hbin
        # could check if size is multiple of 0x1000?
        $offset_to_hbin = $offset_to_prev_hbin + $size_of_prev_hbin;
    }

    sysseek($regfile, $offset_to_hbin, 0);
    sysread($regfile, my $hbin_header, 0x20);
    if (!defined($hbin_header) || length($hbin_header) != 0x20) {
        $self->{_end_of_data} = 1;
        return;
    }

    # 0x00 dword = 'hbin' signature
    # 0x04 dword = offset from 0x1000 (start of first hbin) to this hbin
    # 0x08 dword = size of this hbin / relative offset to next hbin

    my ($sig,
        $offset_from_first_hbin,
        $size_of_hbin) = unpack("a4VV", $hbin_header);

    if ($sig ne "hbin") {
        $self->{_end_of_data} = 1;
        return;
    }

    $self->{_offset_to_hbin} = $offset_to_hbin;
    $self->{_size_of_hbin} = $size_of_hbin;
    $self->{_offset_to_next_entry} = $offset_to_hbin + 0x20;
}

sub move_to_first_entry {
    my $self = shift;
    my $regfile = $self->{_regfile};

    undef $self->{_offset_to_hbin};
    undef $self->{_size_of_hbin};
    undef $self->{_offset_to_next_entry};
    undef $self->{_end_of_data};
}

sub get_next_entry {
    my $self = shift;
    my $regfile = $self->{_regfile};
    my $offset = $self->{_offset_to_next_entry};
    my $offset_to_hbin = $self->{_offset_to_hbin};
    my $size_of_hbin = $self->{_size_of_hbin};

    if (!defined $offset || $offset >= ($offset_to_hbin + $size_of_hbin)) {
        $self->get_next_hbin_header; # may set end of data flag
        # offset, offset_to_hbin, size_of_hbin now need to be refreshed:
        $offset = $self->{_offset_to_next_entry};
        $offset_to_hbin = $self->{_offset_to_hbin};
        $size_of_hbin = $self->{_size_of_hbin};
    }

    if ($self->{_end_of_data}) {
        return;
    }

    if (my $entry = Parse::Win32Registry::WinNT::Entry->new($regfile,
                                                            $offset)) {
        $self->{_offset_to_next_entry} = $offset + $entry->{_size};
        return $entry;
    }
    else {
        $self->{_end_of_data} = 1;
        return;
    }
}

1;
