package Parse::Win32Registry::WinNT::Hbin;

use strict;
use warnings;

use base qw(Parse::Win32Registry::Entry);

use Carp;
use Parse::Win32Registry::Base qw(:all);
use Parse::Win32Registry::WinNT::Entry;

use constant OFFSET_TO_FIRST_HBIN => 0x1000;
use constant HBIN_HEADER_LENGTH => 0x20;

sub new {
    my $class = shift;
    my $regfile = shift;
    my $offset = shift;

    croak "Missing registry file" if !defined $regfile;
    croak "Missing offset" if !defined $offset;

    my $fh = $regfile->{_filehandle};
    croak "Missing filehandle" if !defined $fh;

    # 0x00 dword = 'hbin' signature
    # 0x04 dword = offset from first hbin to this hbin
    # 0x08 dword = length of this hbin / relative offset to next hbin
    # 0x14 qword = timestamp (first hbin only)

    # Extracted offsets are always relative to first HBIN

    sysseek($fh, $offset, 0);
    my $bytes_read = sysread($fh, my $hbin_header, HBIN_HEADER_LENGTH);
    if ($bytes_read != HBIN_HEADER_LENGTH) {
        return;
    }

    my ($sig,
        $offset_to_hbin,
        $length,
        $timestamp) = unpack("a4VVx8a8x4", $hbin_header);

    if ($sig ne "hbin") {
        return;
    }

    my $self = {};
    $self->{_regfile} = $regfile;
    $self->{_offset} = $offset;
    $self->{_length} = $length;
    $self->{_allocated} = 0;
    $self->{_tag} = $sig;
    $self->{_timestamp} = unpack_windows_time($timestamp);
    bless $self, $class;

    return $self;
}

sub get_timestamp {
    my $self = shift;

    return $self->{_timestamp};
}

sub get_timestamp_as_string {
    my $self = shift;

    return iso8601($self->{_timestamp});
}

sub as_string {
    my $self = shift;

    return "(hbin header)";
}

sub parse_info {
    my $self = shift;

    my $info = sprintf '0x%x,%d hbin',
        $self->{_offset},
        $self->{_length};

    return $info;
}

sub unparsed {
    my $self = shift;

    my $regfile = $self->{_regfile};
    croak "Missing registry file" if !defined $regfile;
    my $fh = $regfile->{_filehandle};
    croak "Missing filehandle" if !defined $fh;
    my $offset = $self->{_offset};
    croak "Missing offset" if !defined $offset;
    my $length = $self->{_length};
    croak "Missing length" if !defined $length;

    sysseek($fh, $offset, 0);
    my $bytes_read = sysread($fh, my $buffer, HBIN_HEADER_LENGTH);
    if ($bytes_read == HBIN_HEADER_LENGTH) {
        return hexdump($buffer, $offset);
    }
    else {
        return '';
    }
}

sub get_raw_bytes {
    my $self = shift;

    my $regfile = $self->{_regfile};
    croak "Missing registry file" if !defined $regfile;
    my $fh = $regfile->{_filehandle};
    croak "Missing filehandle" if !defined $fh;
    my $offset = $self->{_offset};
    croak "Missing offset" if !defined $offset;
    my $length = $self->{_length};
    croak "Missing length" if !defined $length;

    sysseek($fh, $offset, 0);
    my $bytes_read = sysread($fh, my $buffer, HBIN_HEADER_LENGTH);
    if ($bytes_read == HBIN_HEADER_LENGTH) {
        return $buffer;
    }
    else {
        return '';
    }
}

sub get_entry_iterator {
    my $self = shift;

    my $regfile = $self->{_regfile};
    croak "Missing registry file" if !defined $regfile;
    my $offset = $self->{_offset};
    croak "Missing offset" if !defined $offset;
    my $length = $self->{_length};
    croak "Missing length" if !defined $length;

    my $offset_to_next_entry = $offset + HBIN_HEADER_LENGTH;
    my $end_of_hbin = $offset + $length;

    return Parse::Win32Registry::Iterator->new(sub {
        if ($offset_to_next_entry >= $end_of_hbin) {
            return; # no more entries
        }
        if (my $entry = Parse::Win32Registry::WinNT::Entry->new($regfile, $offset_to_next_entry)) {
            return unless $entry->get_length > 0;
            $offset_to_next_entry += $entry->get_length;
            return $entry;
        }
        else {
            return; # no more entries
        }
    });
}

1;
