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
use constant CREG_HEADER_LENGTH => 0x20;
use constant RGKN_HEADER_LENGTH => 0x20;
use constant RGDB_HEADER_LENGTH => 0x20;
use constant RGDB_KEY_HEADER_LENGTH => 0x14;

sub new {
    my $class = shift;
    my $filename = shift or croak "No filename specified";

    open my $fh, "<", $filename or croak "Unable to open '$filename': $!";

    # CREG Header
    # 0x00 dword = 'CREG' signature
    # 0x04 dword = some kind of version?
    # 0x08 dword = offset to first rgdb block
    # 0x0c
    # 0x10 word  = number of rgdb blocks

    my $bytes_read = sysread($fh, my $creg_header, CREG_HEADER_LENGTH);
    if ($bytes_read != CREG_HEADER_LENGTH) {
        warnf("Could not read registry file header");
        return;
    }

    my ($creg_sig,
        $offset_to_first_rgdb_block,
        $num_rgdb_blocks) = unpack("a4x4Vx4v", $creg_header);

    if ($creg_sig ne "CREG") {
        warnf("Invalid registry file signature");
        return;
    }

    # RGKN Block Header
    # 0x0 dword = 'RGKN' signature
    # 0x4 dword = length of RGKN block
    # 0x8 dword = offset to root key entry (relative to start of RGKN)

    sysseek($fh, OFFSET_TO_RGKN_BLOCK, 0);
    $bytes_read = sysread($fh, my $rgkn_header, RGKN_HEADER_LENGTH);
    if ($bytes_read != RGKN_HEADER_LENGTH) {
        warnf("Could not read RGKN header at 0x%x", OFFSET_TO_RGKN_BLOCK);
        return;
    }

    my ($rgkn_sig,
        $rgkn_block_length,
        $offset_to_root_key) = unpack("a4VV", $rgkn_header);

    if ($rgkn_sig ne "RGKN") {
        warnf("Invalid RGKN block signature at 0x%x", OFFSET_TO_RGKN_BLOCK);
        return;
    }

    $offset_to_root_key += OFFSET_TO_RGKN_BLOCK;

    my $self = {};
    $self->{_filehandle} = $fh;
    $self->{_filename} = $filename;
    $self->{_length} = (stat $fh)[7];
    $self->{_rgkn_block_length} = $rgkn_block_length;
    $self->{_offset_to_root_key} = $offset_to_root_key;
    $self->{_offset_to_first_rgdb_block} = $offset_to_first_rgdb_block;
    $self->{_num_rgdb_blocks} = $num_rgdb_blocks;
    bless $self, $class;

    # Index the RGDB entries by id for faster look up
    $self->_index_rgdb_entries;

    return $self;
}

sub get_timestamp {
    return undef;
}

sub get_timestamp_as_string {
    return iso8601(undef);
}

sub get_embedded_filename {
    return undef;
}

sub get_root_key {
    my $self = shift;

    my $offset_to_root_key = $self->{_offset_to_root_key};

    my $root_key = Parse::Win32Registry::Win95::Key->new($self,
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

sub _index_rgdb_entries {
    my $self = shift;

    my $fh = $self->{_filehandle};
    croak "Missing filehandle" if !defined $fh;

    my %index = ();

    my $offset_to_rgdb_block = $self->{_offset_to_first_rgdb_block};
    croak "Missing offset to rgdb block" if !defined $offset_to_rgdb_block;
    my $num_rgdb_blocks = $self->{_num_rgdb_blocks};
    croak "Missing number of rgdb blocks" if !defined $num_rgdb_blocks;

    foreach my $rgdb_block_num (0..($num_rgdb_blocks-1)) {
        # RGDB Block Header
        # 0x0 dword = 'RDGB' signature
        # 0x4 dword = RGDB block length

        sysseek($fh, $offset_to_rgdb_block, 0);
        my $bytes_read = sysread($fh, my $rgdb_header, RGDB_HEADER_LENGTH);
        if ($bytes_read != RGDB_HEADER_LENGTH) {
            last; # skip further processing
        }

        my ($sig,
            $rgdb_block_length) = unpack("a4V", $rgdb_header);

        if ($sig ne "RGDB") {
            last; # skip further processing
        }

        # move to first entry in RGDB block
        my $offset_to_rgdb_entry = $offset_to_rgdb_block + RGDB_HEADER_LENGTH;
        my $end_of_rgdb_block = $offset_to_rgdb_block + $rgdb_block_length;

        while ($offset_to_rgdb_entry < $end_of_rgdb_block) {
            # RGDB Key Entry
            # 0x00 dword = entry length / offset to next key entry
            #              (this length includes any following value entries)
            # 0x04 dword = id (top word = block num, bottom word = id)
            # 0x04 word  = id
            # 0x06 word  = block_num
            # 0x08 dword = bytes used (unpacked, but not used)
            # 0x0c word  = key name length
            # 0x0e word  = number of values
            # 0x10 dword
            # 0x14       = key name [for name length bytes]
            # this is followed immediately by RGDB Value Entries

            sysseek($fh, $offset_to_rgdb_entry, 0);
            $bytes_read = sysread($fh, my $rgdb_key_entry, RGDB_KEY_HEADER_LENGTH);
            if ($bytes_read != RGDB_KEY_HEADER_LENGTH) {
                last; # skip further processing
            }

            my ($rgdb_entry_length,
                $rgdb_entry_id,
                $bytes_used,
                $name_length,
                $num_values) = unpack("VVVvv", $rgdb_key_entry);

            my $rgdb_entry_block_num = $rgdb_entry_id >> 16;
            if ($rgdb_block_num == $rgdb_entry_block_num) {
                $bytes_read = sysread($fh, my $name, $name_length);
                if ($bytes_read == $name_length) {
                    $index{$rgdb_entry_id} = {
                        _offset_to_rgdb_entry => $offset_to_rgdb_entry,
                        _rgdb_entry_length => $rgdb_entry_length,
                        _name => $name,
                        _name_length => $name_length,
                        _num_values => $num_values,
                        _bytes_used => $bytes_used,
                    };
                }
            }

            last unless $rgdb_entry_length > 0;
            $offset_to_rgdb_entry += $rgdb_entry_length;
        }

        last unless $rgdb_block_length > 0;
        $offset_to_rgdb_block += $rgdb_block_length;
    }

    $self->{_rgdb_index} = \%index;
}

sub _dump_rgdb_index {
    my $self = shift;

    my $index = $self->{_rgdb_index};
    croak "Missing rgdb index" if !defined $index;

    printf "RGDB Index: %d rgdb blocks starting at 0x%x\n",
        $self->{_num_rgdb_blocks},
        $self->{_offset_to_first_rgdb_block};

    foreach my $rgdb_entry_id (sort { $a <=> $b } keys %{$index}) {
        printf qq{id=0x%x 0x%x,%d/%d "%s" vals=%d\n},
            $rgdb_entry_id,
            $index->{$rgdb_entry_id}{_offset_to_rgdb_entry},
            $index->{$rgdb_entry_id}{_bytes_used},
            $index->{$rgdb_entry_id}{_rgdb_entry_length},
            $index->{$rgdb_entry_id}{_name},
            $index->{$rgdb_entry_id}{_num_values};
    }
}

sub get_hbin_iterator {
    return;
}

sub get_entry_iterator {
    my $self = shift;

    my $rgkn_block_length = $self->{_rgkn_block_length};

    my $offset_to_next_entry = OFFSET_TO_RGKN_BLOCK + RGKN_HEADER_LENGTH;
    my $end_of_rgkn_block = OFFSET_TO_RGKN_BLOCK + $rgkn_block_length;

    return Parse::Win32Registry::Iterator->new(sub {
        if ($offset_to_next_entry >= $end_of_rgkn_block) {
            return; # no more entries
        }
        if (my $entry = Parse::Win32Registry::Win95::Entry->new($self, $offset_to_next_entry)) {
            $offset_to_next_entry += $entry->get_length;
            return $entry;
        }
        else {
            return; # no more entries
        }
    });
}

1;
