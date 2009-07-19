package Parse::Win32Registry::Win95::Key;

use strict;
use warnings;

use base qw(Parse::Win32Registry::Key);

use Carp;
use Parse::Win32Registry::Base qw(:all);
use Parse::Win32Registry::Win95::Value;

use constant OFFSET_TO_RGKN_BLOCK => 0x20;
use constant RGKN_ENTRY_LENGTH => 0x1c;

sub new {
    my $class = shift;
    my $regfile = shift;
    my $offset = shift; # offset to RGKN key entry relative to start of RGKN
    my $parent_key_path = shift; # parent key path (optional)

    croak "Missing registry file" if !defined $regfile;
    croak "Missing offset" if !defined $offset;

    # when errors are encountered
    my $whereabouts = defined($parent_key_path)
                    ? " (a subkey of '$parent_key_path')"
                    : "";

    my $fh = $regfile->{_filehandle};
    croak "Missing filehandle" if !defined $fh;

    # RGKN Key Entry
    # 0x00 dword
    # 0x04 dword = hash (unpacked, but not used)
    # 0x08 dword
    # 0x0c dword = offset to parent RGKN entry
    # 0x10 dword = offset to first child RGKN entry
    # 0x14 dword = offset to next sibling RGKN entry
    # 0x18 dword = entry id of RGDB entry

    # Extracted offsets are relative to the start of the RGKN block

    # Any offset of 0xffffffff marks the end of a list.
    # An entry id of 0xffffffff means the RGKN entry has no RGDB entry.
    # This occurs for the root key of the registry file.

    sysseek($fh, $offset, 0);
    my $bytes_read = sysread($fh, my $rgkn_entry, RGKN_ENTRY_LENGTH);
    if ($bytes_read != RGKN_ENTRY_LENGTH) {
        warnf("Could not read RGKN key at 0x%x%s",
            $offset, $whereabouts);
        return;
    }

    my ($hash,
        $offset_to_parent,
        $offset_to_first_child,
        $offset_to_next_sibling,
        $rgkn_entry_id) = unpack("x4Vx4VVVV", $rgkn_entry);

    $offset_to_parent += OFFSET_TO_RGKN_BLOCK
        if $offset_to_parent != 0xffffffff;
    $offset_to_first_child += OFFSET_TO_RGKN_BLOCK
        if $offset_to_first_child != 0xffffffff;
    $offset_to_next_sibling += OFFSET_TO_RGKN_BLOCK
        if $offset_to_next_sibling != 0xffffffff;

    my $self = {};
    $self->{_regfile} = $regfile;
    $self->{_offset} = $offset;
    $self->{_length} = RGKN_ENTRY_LENGTH;
    $self->{_allocated} = 0;
    $self->{_tag} = "rgkn";
    $self->{_offset_to_parent} = $offset_to_parent;
    $self->{_offset_to_first_child} = $offset_to_first_child;
    $self->{_offset_to_next_sibling} = $offset_to_next_sibling;
    $self->{_rgkn_entry_id} = $rgkn_entry_id;
    bless $self, $class;

    # Look up rgdb blocks for key matching $rgkn_entry_id
    my $index = $regfile->{_rgdb_index};
    croak "Missing rgdb index" if !defined $index;
    if (exists $index->{$rgkn_entry_id}) {
        my $rgdb_entry = $index->{$rgkn_entry_id};
        $self->{_name} = $rgdb_entry->{_name};
        $self->{_rgdb_entry_length} = $rgdb_entry->{_rgdb_entry_length};
        $self->{_offset_to_rgdb_entry} = $rgdb_entry->{_offset_to_rgdb_entry};
        $self->{_num_values} = $rgdb_entry->{_num_values};
        $self->{_bytes_used} = $rgdb_entry->{_bytes_used};
    }
    else {
        # No matching RGDB entry, set safe defaults:
        $self->{_name} = '';
        $self->{_num_values} = 0;

        # Only the root key should have no matching RGDB entry
        if (!$self->is_root) {
            warnf("Could not find RGDB entry for RGKN key at 0x%x%s",
                $offset, $whereabouts);
        }
    }

    my $name = $self->{_name};
    $self->{_key_path} = defined($parent_key_path)
                       ? "$parent_key_path\\$name"
                       : $name;

    return $self;
}

sub get_timestamp {
    return undef;
}

sub get_timestamp_as_string {
    return iso8601(undef);
}

sub get_class_name {
    return undef;
}

sub is_root {
    my $self = shift;

    my $offset = $self->{_offset};
    croak "Missing offset" if !defined $offset;
    my $regfile = $self->{_regfile};
    croak "Missing registry file" if !defined $regfile;
    my $offset_to_root_key = $regfile->{_offset_to_root_key};
    croak "Missing offset to root key" if !defined $offset_to_root_key;

    # This gives better results than checking id == 0xffffffff
    return $offset == $offset_to_root_key;
}

sub get_parent {
    my $self = shift;

    my $regfile = $self->{_regfile};
    my $offset_to_parent = $self->{_offset_to_parent};
    my $key_path = $self->{_key_path};

    return if $self->is_root;

    my $parent_key_path;
    my @keys = split(/\\/, $key_path, -1);
    if (@keys > 2) {
        $parent_key_path = join("\\", @keys[0..$#keys-2]);
    }

    return Parse::Win32Registry::Win95::Key->new($regfile,
                                                 $offset_to_parent,
                                                 $parent_key_path);
}

sub get_security {
    return undef;
}

sub as_string {
    my $self = shift;

    return $self->get_path;
}

sub parse_info {
    my $self = shift;

    my $info = sprintf '0x%x,%d rgkn id=0x%x par=0x%x,child=0x%x,next=0x%x',
        $self->{_offset},
        $self->{_length},
        $self->{_rgkn_entry_id},
        $self->{_offset_to_parent},
        $self->{_offset_to_first_child},
        $self->{_offset_to_next_sibling};
    if (defined($self->{_offset_to_rgdb_entry})) {
        $info .= sprintf ' | 0x%x,%d/%d rgdb "%s" vals=%d',
            $self->{_offset_to_rgdb_entry},
            $self->{_bytes_used},
            $self->{_rgdb_entry_length},
            $self->{_name},
            $self->{_num_values};
    }
    return $info;
}

sub get_subkey_iterator {
    my $self = shift;

    my $regfile = $self->{_regfile};
    croak "Missing registry file" if !defined $regfile;
    my $key_path = $self->{_key_path};

    my $offset_to_next_key = $self->{_offset_to_first_child};
    croak "Missing offset to first child" if !defined $offset_to_next_key;

    my $end_of_file = $regfile->{_length};
    my $end_of_rgkn_block = OFFSET_TO_RGKN_BLOCK
                          + $regfile->{_rgkn_block_length};

    return Parse::Win32Registry::Iterator->new(sub {
        if ($offset_to_next_key == 0xffffffff) {
            return; # no more subkeys
        }
        if ($offset_to_next_key > $end_of_rgkn_block) {
            return;
        }
        if (my $key = Parse::Win32Registry::Win95::Key->new($regfile, $offset_to_next_key, $key_path)) {
            $offset_to_next_key = $key->{_offset_to_next_sibling};
            return $key;
        }
        else {
            return; # no more subkeys
        }
    });
}

sub get_value_iterator {
    my $self = shift;

    my $regfile = $self->{_regfile};
    croak "Missing registry file" if !defined $regfile;

    my $key_path = $self->{_key_path};

    my $num_values_remaining = $self->{_num_values};
    croak "Missing number of values" if !defined $num_values_remaining;

    my $end_of_file = $regfile->{_length};
    croak "Missing length" if !defined $end_of_file;

    # offset_to_next_rgdb_value can only be set to a valid offset
    # if offset_to_rgdb_entry is defined and num_values_remaining > 0
    my $offset_to_rgdb_entry = $self->{_offset_to_rgdb_entry};
    my $offset_to_next_rgdb_value = 0xffffffff;
    if (defined $offset_to_rgdb_entry && $num_values_remaining > 0) {
        $offset_to_next_rgdb_value = $offset_to_rgdb_entry
                                   + 0x14 + length($self->{_name});
    }

    return Parse::Win32Registry::Iterator->new(sub {
        if ($num_values_remaining-- <= 0) {
            return;
        }
        if ($offset_to_next_rgdb_value == 0xffffffff) {
            return;
        }
        if ($offset_to_next_rgdb_value > $end_of_file) {
            return;
        }
        if (my $value = Parse::Win32Registry::Win95::Value->new($regfile, $offset_to_next_rgdb_value, $key_path)) {
            $offset_to_next_rgdb_value += $value->{_length};
            return $value;
        }
        else {
            return; # no more values
        }
    });
}

1;
