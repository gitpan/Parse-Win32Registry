package Parse::Win32Registry::Win95::Key;

use strict;
use warnings;

use base qw(Parse::Win32Registry::Key);

use Carp;
use Parse::Win32Registry::Base qw(:all);
use Parse::Win32Registry::Win95::Value;

use constant OFFSET_TO_RGKN_BLOCK => 0x20;
use constant RGKN_ENTRY_SIZE => 28;

sub new {
    my $class = shift;
    my $regfile = shift;
    my $offset = shift; # offset to RGKN key entry relative to start of RGKN
    my $parent_key_path = shift; # parent key path (optional)

    die "unexpected error: undefined regfile" if !defined $regfile;
    die "unexpected error: undefined offset" if !defined $offset;
    
    # when errors are encountered
    my $whereabouts = (defined $parent_key_path)
                    ? " (a subkey of $parent_key_path)"
                    : "";

    # RGKN Key Entry
    # 0x00 dword
    # 0x04 dword = hash (unpacked, but not used)
    # 0x08 dword
    # 0x0c dword = offset to parent RGKN entry
    # 0x10 dword = offset to first child RGKN entry
    # 0x14 dword = offset to next sibling RGKN entry
    # 0x18 word  = id of RGDB entry
    # 0x1a word  = number of RGDB block

    # Extracted offsets are relative to the start of the RGKN block

    # Any offset of 0xffffffff marks the end of a list.
    # An id and block_num of 0xffff means the RGKN entry has no RGDB entry. 
    # This occurs for the root key's RGKN entry
    # (and presumably also for invalid RGKN entries).

    sysseek($regfile, $offset, 0);
    sysread($regfile, my $rgkn_entry, 28);
    if (!defined($rgkn_entry) || length($rgkn_entry) != 28) {
        log_error("Could not read RGKN entry for key at 0x%x%s", 
            $offset, $whereabouts);
        return;
    }

    my ($hash,
        $offset_to_parent,
        $offset_to_first_child,
        $offset_to_next_sibling,
        $rgkn_key_id,
        $rgkn_block_num) = unpack("x4Vx4VVVvv", $rgkn_entry);

    $offset_to_parent += OFFSET_TO_RGKN_BLOCK
        if $offset_to_parent != 0xffffffff;
    $offset_to_first_child += OFFSET_TO_RGKN_BLOCK
        if $offset_to_first_child != 0xffffffff;
    $offset_to_next_sibling += OFFSET_TO_RGKN_BLOCK
        if $offset_to_next_sibling != 0xffffffff;

    my $self = {};
    $self->{_regfile} = $regfile;
    $self->{_offset} = $offset;
    $self->{_offset_to_parent} = $offset_to_parent;
    $self->{_offset_to_first_child} = $offset_to_first_child;
    $self->{_offset_to_next_sibling} = $offset_to_next_sibling;
    $self->{_rgkn_key_id} = $rgkn_key_id;
    $self->{_rgkn_block_num} = $rgkn_block_num;
    bless $self, $class;

    $self->{_name} = '';       # default, overridden by look_up_rgdb_entry
    $self->{_name_length} = 0; # default, overridden by look_up_rgdb_entry
    $self->{_num_values} = 0;  # default, overridden by look_up_rgdb_entry
    # $self->{_offset_to_rgdb_entry} should also be set by look_up_rgdb_entry

    $self->{_key_path} = '';   # default, overridden after name looked up

    # remember the _parent_key_path in for errors in look_up_rgdb_entry
    $self->{_parent_key_path} = $parent_key_path;

    # look up RGDB entry to determine the key's name and number of values
    if ($self->_look_up_rgdb_entry) {
        # _name should now be defined (if they were found)
        my $name = $self->{_name};
        $self->{_key_path} = (defined $parent_key_path)
                           ? "$parent_key_path\\$name"
                           : $name;
    }

    return $self;
}

sub _look_up_rgdb_entry {
    my $self = shift;

    my $regfile = $self->{_regfile};
    my $offset = $self->{_offset};
    my $rgkn_key_id = $self->{_rgkn_key_id};
    my $rgkn_block_num = $self->{_rgkn_block_num};

    die "unexpected error: undefined regfile"
        if !defined($regfile);
    die "unexpected error: undefined rgkn_key_id"
        if !defined($rgkn_key_id);
    die "unexpected error: undefined rgkn_block_num"
        if !defined($rgkn_block_num);

    # The root key has an id of 0xffff and a block_num of 0xffff
    # and this cannot be successfully looked up in the RGDB blocks,
    # so abandon the attempt. The fields _name, _offset_to_rgdb_entry,
    # and _num_values may be set to something other than undef.
    if ($rgkn_key_id == 0xffff || $rgkn_block_num == 0xffff) {
        $self->{_name} = ""; # or "NONAME"?
        $self->{_num_values} = 0;
        #$self->{_offset_to_rgdb_entry} = undef;
        return 1;
    }

    # when errors are encountered
    my $parent_key_path = $self->{_parent_key_path};
    my $whereabouts = (defined $parent_key_path)
                    ? " (looking up a subkey of $parent_key_path)"
                    : "";

    # get offset to first RGDB block from CREG header
    sysseek($regfile, 0, 0);
    sysread($regfile, my $creg_header, 32);
    if (!defined($creg_header) || length($creg_header) != 32) {
        log_error("Could not read registry file header%s", $whereabouts);
        return;
    }

    # start from the offset to the first RGDB block
    my ($offset_to_rgdb_block,
        $num_rgdb_blocks) = unpack("x8Vx4v", $creg_header);

    if ($rgkn_block_num >= $num_rgdb_blocks) {
        log_error("Invalid RGKN block number for key at 0x%x%s",
            $offset, $whereabouts);
        return;
    }

    # skip block_num RGDB blocks:
    foreach my $rgdb_block_num (0..$num_rgdb_blocks-1) {

        # RGDB Block Header
        # 0x0 dword = 'RDGB' signature 
        # 0x4 dword = RGDB block size

        sysseek($regfile, $offset_to_rgdb_block, 0);
        sysread($regfile, my $rgdb_header, 32);
        if (!defined($rgdb_header) || length($rgdb_header) != 32) {
            log_error("Could not read RGDB block header at 0x%x%s",
                $offset_to_rgdb_block, $whereabouts);
            return;
        }

        my ($sig, $rgdb_block_size) = unpack("a4V", $rgdb_header);
        if ($sig ne "RGDB") {
            log_error("Invalid RGDB block signature at 0x%x%s",
                $offset_to_rgdb_block, $whereabouts);
            return;
        }

        if ($rgkn_block_num == $rgdb_block_num) {
            # found the RGDB block
            return $self->_look_up_entry_in_rgdb_block($offset_to_rgdb_block,
                                                       $rgdb_block_size);
        }
        else {
            if ($rgdb_block_size < 32) {
                log_error("Block size of 0x%x smaller than expected " . 
                    "for RGDB block at 0x%x%s",
                    $rgdb_block_size, $offset_to_rgdb_block, $whereabouts);
                return;
            }
            $offset_to_rgdb_block += $rgdb_block_size;
        }
    }

    # Cannot reach this point without
    # 1. finding the matching entry
    # 2. finding the right block but not the matching entry
    #    (fails with: "Could not find RGDB entry for key at ...")
    # 3. not finding the block because the RGKN block number was too large
    #    (fails with: "Invalid RGKN block number for key at ...")
    # 4. not finding the block because the RGDB block did not exist
    #    (fails with: "Could not read RGDB block header at ...")
}

sub _look_up_entry_in_rgdb_block {
    my $self = shift;
    my $offset_to_rgdb_block = shift;
    my $rgdb_block_size = shift;

    die "unexpected error: undefined offset_to_rgdb_block"
        if !defined($offset_to_rgdb_block);
    die "unexpected error: undefined rgdb_block_size"
        if !defined($rgdb_block_size);

    my $regfile = $self->{_regfile};
    my $offset = $self->{_offset};
    my $rgkn_key_id = $self->{_rgkn_key_id};
    my $rgkn_block_num = $self->{_rgkn_block_num};

    die "unexpected error: undefined regfile"
        if !defined($regfile);
    die "unexpected error: undefined rgkn_key_id"
        if !defined($rgkn_key_id);
    die "unexpected error: undefined rgkn_block_num"
        if !defined($rgkn_block_num);

    # when errors are encountered
    my $parent_key_path = $self->{_parent_key_path};
    my $whereabouts = (defined $parent_key_path)
                    ? " (looking up a subkey of $parent_key_path)"
                    : "";

    # The first record in the RGDB block
    # begins immediately after the RGDB header
    my $offset_to_rgdb_entry = $offset_to_rgdb_block + 32;

    while ($offset_to_rgdb_entry < $offset_to_rgdb_block + $rgdb_block_size) {

        # RGDB Key Entry
        # 0x00 dword = entry size / offset to next key entry
        #              (this size includes any following value entries)
        # 0x04 word  = id
        # 0x06 word  = block_num
        # 0x08 dword = bytes used (unpacked, but not used)
        # 0x0c word  = key name length
        # 0x0e word  = number of values
        # 0x10 dword
        # 0x14       = key name [for name length bytes]
        # this is followed immediately by RGDB Value Entries

        sysseek($regfile, $offset_to_rgdb_entry, 0);
        sysread($regfile, my $rgdb_key_entry, 0x14);
        if (!defined($rgdb_key_entry) || length($rgdb_key_entry) != 0x14) {
            log_error("Could not read RGDB entry for key at 0x%x%s",
                $offset_to_rgdb_entry, $whereabouts);
            return;
        }

        my ($rgdb_entry_size,
            $rgdb_key_id,
            $rgdb_block_num,
            $bytes_used,
            $name_length,
            $num_values) = unpack("VvvVvv", $rgdb_key_entry);

        if ($rgdb_key_id == $rgkn_key_id) {
            # found a match (id is checked, block_num is not)

            sysread($regfile, my $name, $name_length);
            if (!defined($name) || length($name) != $name_length) {
                log_error("Could not read RGDB entry name for key at 0x%x%s",
                    $offset_to_rgdb_entry, $whereabouts);
                return;
            }

            $self->{_name} = $name;
            $self->{_name_length} = $name_length;
            $self->{_offset_to_rgdb_entry} = $offset_to_rgdb_entry;
            $self->{_num_values} = $num_values;

            return 1;
        }

        if ($rgdb_entry_size < 16) {
            log_error("Entry size of 0x%x smaller than expected " .
                "for RGDB entry at 0x%x%s",
                $rgdb_entry_size, $offset_to_rgdb_entry, $whereabouts);
            return;
        }
        $offset_to_rgdb_entry += $rgdb_entry_size;
    }

    # Reached end of RGDB block without finding matching id
    $whereabouts =~ s/looking up//;
    log_error("Could not find RGDB entry for key at 0x%x%s",
        $offset, $whereabouts);
    return;
}

sub get_timestamp {
    return undef;
}

sub get_timestamp_as_string {
    return iso8601(undef);
}

sub get_type {
    return undef;
}

sub is_root {
    my $self = shift;

    my $rgkn_key_id = $self->{_rgkn_key_id};
    my $rgkn_block_num = $self->{_rgkn_block_num};

    return $rgkn_key_id == 0xffff && $rgkn_block_num == 0xffff;
}

sub get_parent {
    my $self = shift;

    my $regfile = $self->{_regfile};
    my $offset_to_parent = $self->{_offset_to_parent};

    return if $self->is_root;

    my $parent_key_path;
    my @keys = split /\\/, $self->{_key_path}, -1;
    if (@keys > 2) {
        $parent_key_path = join("\\", @keys[0..$#keys-2]);
    }

    return Parse::Win32Registry::Win95::Key->new($regfile, $offset_to_parent,
                                                           $parent_key_path);
}

sub get_class_name {
    return undef;
}

sub as_string {
    my $self = shift;

    return $self->get_path;
}

sub print_summary {
    my $self = shift;

    print $self->as_string, "\n";
}

sub parse_info {
    my $self = shift;

    my $string = sprintf 'rgkn=0x%x id=0x%x,0x%x par=0x%x,child=0x%x,next=0x%x',
        $self->{_offset},
        $self->{_rgkn_key_id},
        $self->{_rgkn_block_num},
        $self->{_offset_to_parent},
        $self->{_offset_to_first_child},
        $self->{_offset_to_next_sibling};

    if (defined($self->{_offset_to_rgdb_entry})) {
        $string .= sprintf ' | rgdb=0x%x "%s" vals=%d',
            $self->{_offset_to_rgdb_entry},
            $self->{_name},
            $self->{_num_values};
    }

    return $string;
}

sub as_hexdump {
    my $self = shift;
    my $regfile = $self->{_regfile};

    my $hexdump = '';

    sysseek($regfile, $self->{_offset}, 0);
    sysread($regfile, my $buffer, 28);
    $hexdump .= hexdump($buffer, $self->{_offset});

    if (defined($self->{_offset_to_rgdb_entry})) {
        sysseek($regfile, $self->{_offset_to_rgdb_entry}, 0);
        sysread($regfile, $buffer, 0x14 + $self->{_name_length});
        $hexdump .= hexdump($buffer, $self->{_offset_to_rgdb_entry});
    }

    return $hexdump;
}

sub get_list_of_subkeys {
    my $self = shift;

    my $regfile = $self->{_regfile};
    my $key_path = $self->{_key_path};
    my $offset_to_first_child = $self->{_offset_to_first_child};

    # when errors are encountered
    my $whereabouts = (defined $key_path)
                    ? " (when enumerating subkeys of $key_path)"
                    : "";
    
    my @subkeys = ();

    if ($offset_to_first_child != 0xffffffff) {
        if (my $key = Parse::Win32Registry::Win95::Key->new($regfile,
                      $offset_to_first_child, $key_path)) {
            push @subkeys, $key;
            while ($key->{_offset_to_next_sibling} != 0xffffffff) {
                if ($key = Parse::Win32Registry::Win95::Key->new($regfile,
                           $key->{_offset_to_next_sibling}, $key_path)) {
                    push @subkeys, $key;
                }
                else {
                    log_error("Skipping further keys, " .
                        "as each is required to find the following key%s",
                        $whereabouts);
                    last;
                }
            }
        }
        else {
            log_error("Skipping further keys, " .
                "as first is required to find the following key%s",
                $whereabouts);
        }
    }
    return @subkeys;
}

sub get_list_of_values {
    my $self = shift;

    my $regfile = $self->{_regfile};

    return () if $self->{_num_values} == 0;

    # when errors are encountered
    my $key_path = $self->{_key_path};
    my $whereabouts = (defined $key_path)
                    ? " (when enumerating values of $key_path)"
                    : "";

    my @values = ();

    # first RGDB value record starts after the end of the RGDB key record
    # length of a RGDB key record header is 0x14 
    my $offset_to_first_rgdb_value_entry
        = $self->{_offset_to_rgdb_entry} + 0x14 + length($self->{_name});
    sysseek($regfile, $offset_to_first_rgdb_value_entry, 0);

    my $offset_to_rgdb_value_entry = $offset_to_first_rgdb_value_entry;

    foreach (1..$self->{_num_values}) {
        if (my $value = Parse::Win32Registry::Win95::Value->new($regfile,
                        $offset_to_rgdb_value_entry, $key_path)) {
            push @values, $value;
            if ($value->{_size} < 12) {
                log_error(
                    "RGDB entry size smaller than expected for value at 0x%x%s",
                    $offset_to_rgdb_value_entry, $whereabouts);
                return;
            }
            $offset_to_rgdb_value_entry += $value->{_size};
        }
        else {
            log_error(
                "Skipping further values, as values are stored sequentially%s",
                $whereabouts);
            last;
        }
    }
    return @values;
}

1;
