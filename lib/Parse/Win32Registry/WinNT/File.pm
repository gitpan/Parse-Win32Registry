package Parse::Win32Registry::WinNT::File;

use strict;
use warnings;

use base qw(Parse::Win32Registry::File);

use Carp;
use Encode;
use File::Basename;
use Parse::Win32Registry::Base qw(:all);
use Parse::Win32Registry::WinNT::Key;
use Parse::Win32Registry::WinNT::Hbin;

use constant OFFSET_TO_FIRST_HBIN => 0x1000;
use constant REGF_HEADER_LENGTH => 0x200;

sub new {
    my $class = shift;
    my $filename = shift or croak "No filename specified";

    open my $fh, "<", $filename or croak "Unable to open '$filename': $!";

    # 0x00 dword = 'regf' signature
    # 0x04 dword = seq1
    # 0x08 dword = seq2
    # 0x0c qword = timestamp
    # 0x14 dword = major version
    # 0x18 dword = minor version
    # 0x1c dword = type (0 = registry file, 1 = log file)
    # 0x20 dword = (1)
    # 0x24 dword = offset to root key
    # 0x28 dword = total length of all hbins (excludes header)
    # 0x2c dword = (1)
    # 0x30       = embedded filename

    # Extracted offsets are always relative to first HBIN

    my $bytes_read = sysread($fh, my $regf_header, REGF_HEADER_LENGTH);
    if ($bytes_read != REGF_HEADER_LENGTH) {
        warnf("Could not read registry file header");
        return;
    }

    my ($regf_sig,
        $seq1,
        $seq2,
        $timestamp,
        $major_version,
        $minor_version,
        $type,
        $offset_to_root_key,
        $total_hbin_length,
        $embedded_filename,
        ) = unpack("a4VVa8VVVx4VVx4a64", $regf_header);

    $offset_to_root_key += OFFSET_TO_FIRST_HBIN;

    if ($regf_sig ne "regf") {
        warnf("Invalid registry file signature");
        return;
    }

    $embedded_filename = unpack("Z*", decode("UCS-2LE", $embedded_filename));

    # The header checksum is the xor of the first 127 dwords.
    # The checksum is stored in the 128th dword, at offset 0x1fc (508).
    my $checksum = 0;
    foreach my $x (unpack("V127", $regf_header)) {
        $checksum ^= $x;
    }
    my $embedded_checksum = unpack("x508V", $regf_header);
    if ($checksum != $embedded_checksum) {
        warnf("Invalid checksum for registry file header");
    }

    my $self = {};
    $self->{_filehandle} = $fh;
    $self->{_filename} = $filename;
    $self->{_length} = (stat $fh)[7];
    $self->{_offset_to_root_key} = $offset_to_root_key;
    $self->{_timestamp} = unpack_windows_time($timestamp);
    $self->{_embedded_filename} = $embedded_filename;
    $self->{_seq1} = $seq1;
    $self->{_seq2} = $seq2;
    $self->{_version} = "$major_version.$minor_version";
    $self->{_type} = $type;
    $self->{_total_hbin_length} = $total_hbin_length;
    $self->{_embedded_checksum} = $embedded_checksum;
    $self->{_security_cache} = {}; # comment out to disable cache
    bless $self, $class;

    return $self;
}

sub get_root_key {
    my $self = shift;

    my $offset_to_root_key = $self->{_offset_to_root_key};

    my $root_key = Parse::Win32Registry::WinNT::Key->new($self,
                                                         $offset_to_root_key);
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

sub get_hbin_iterator {
    my $self = shift;

    my $offset_to_next_hbin = OFFSET_TO_FIRST_HBIN;
    my $end_of_file = $self->{_length};

    return Parse::Win32Registry::Iterator->new(sub {
        if ($offset_to_next_hbin > $end_of_file) {
            return; # no more hbins
        }
        if (my $hbin = Parse::Win32Registry::WinNT::Hbin->new($self, $offset_to_next_hbin)) {
            return unless $hbin->get_length > 0;
            $offset_to_next_hbin += $hbin->get_length;
            return $hbin;
        }
        else {
            return; # no more hbins
        }
    });
}

sub get_entry_iterator {
    my $self = shift;

    my $entry_iter;
    my $hbin_iter = $self->get_hbin_iterator;

    return Parse::Win32Registry::Iterator->new(sub {
        while (1) {
            if (defined $entry_iter) {
                my $entry = $entry_iter->();
                if (defined $entry) {
                    return $entry;
                }
            }
            # entry iterator is undefined or finished so fetch a new one
            my $hbin = $hbin_iter->();
            if (!defined $hbin) {
                return; # hbin iterator finished
            }
            $entry_iter = $hbin->get_entry_iterator;
        }
    });
}

sub _dump_security_cache {
    my $self = shift;

    if (defined(my $cache = $self->{_security_cache})) {
        foreach my $offset (sort { $a <=> $b } keys %$cache) {
            my $security = $cache->{$offset};
            printf "0x%x %s\n", $offset, $security->as_string;
        }
    }
}

1;
