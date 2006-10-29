package Parse::Win32Registry::Win95::Key;

use strict;
use warnings;

use base qw(Parse::Win32Registry::Key);

use Parse::Win32Registry qw(as_iso8601 hexdump);
use Parse::Win32Registry::Win95::Value;

use Carp;

use constant OFFSET_TO_RGKN_BLOCK => 0x20;
use constant RGKN_ENTRY_SIZE => 28;

sub new {
    my $class = shift;
    my $regfile = shift;
    my $offset = shift; # offset to RGKN key entry relative to start of file
    my $path = shift; # optional path from parent

    die "unexpected error: undefined regfile" if !defined $regfile;
    die "unexpected error: undefined offset" if !defined $offset;

    my $self = {};
    $self->{_regfile} = $regfile;
    $self->{_offset} = $offset;

    # offset is a pointer to RGKN entry, relative to start of RGKN

    die if $offset == 0xffffffff;

    sysseek($regfile, $offset, 0);
    sysread($regfile, my $rgkn_entry, 28);
    if (!defined($rgkn_entry) || length($rgkn_entry) != 28) {
        croak "Could not read RGKN entry for key at offset ",
            sprintf("0x%x\n", $offset);
    }

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

    $self->{_hash} = $hash;
    $self->{_offset_to_parent} = $offset_to_parent;
    $self->{_offset_to_first_child} = $offset_to_first_child;
    $self->{_offset_to_next_sibling} = $offset_to_next_sibling;
    $self->{_rgkn_key_id} = $rgkn_key_id;
    $self->{_rgkn_block_num} = $rgkn_block_num;

    bless $self, $class;

    # look up RGDB entry to determine the key's name and value list
	$self->_look_up_rgdb_entry;
	
    my $name = $self->{_name};
    if (defined($path)) {
        $path .= "\\$name";
    }
    else {
        $path = $name;
    }
    $self->{_path} = $path;

    return $self;
}

sub _look_up_rgdb_entry {
	my $self = shift;

    my $regfile = $self->{_regfile};
    my $offset = $self->{_offset};
    my $rgkn_key_id = $self->{_rgkn_key_id};
    my $rgkn_block_num = $self->{_rgkn_block_num};

    die "unexpected error: undefined regfile" if !defined($regfile);
    die "unexpected error: undefined rgkn_key_id" if !defined($rgkn_key_id);
    die "unexpected error: undefined rgkn_block_num" if !defined($rgkn_block_num);

    # The root key has an id of 0xffff and a block_num of 0xffff
    # and this cannot be successfully looked up in the RGDB blocks,
    # so abandon the attempt. The fields _name, _offset_to_rgdb_entry,
    # and _num_values may be set to something other than undef.
    if ($rgkn_key_id == 0xffff || $rgkn_block_num == 0xffff) {
        $self->{_name} = ""; # or "NONAME"?
        $self->{_num_values} = 0;
        #$self->{_offset_to_rgdb_entry} = undef;
        return;
    }

    # get offset to first RGDB block from CREG header
    sysseek($regfile, 0, 0);
    sysread($regfile, my $creg_header, 32);
    if (!defined($creg_header) || length($creg_header) != 32) {
        croak "Could not read registry file header\n";
    }

    # start from the offset to the first RGDB block
    my ($offset_to_rgdb_block,
        $num_rgdb_blocks) = unpack("x8 V x4 v", $creg_header);

    if ($rgkn_block_num >= $num_rgdb_blocks) {
        croak "Invalid RGKN block number for key at offset ",
            sprintf("0x%x", $offset);
    }

    # skip block_num RGDB blocks:
    foreach my $rgdb_block_num (0..$num_rgdb_blocks-1) {

        # RGDB Block Header
        # 0x0 dword = 'RDGB' signature 
        # 0x4 dword = RGDB block size

        sysseek($regfile, $offset_to_rgdb_block, 0);
        sysread($regfile, my $rgdb_header, 32);
        if (!defined($rgdb_header) || length($rgdb_header) != 32) {
            croak "Could not read RGDB block header at offset ",
                sprintf("0x%x\n", $offset_to_rgdb_block);
        }

        my ($sig, $rgdb_block_size) = unpack("a4V", $rgdb_header);
        if ($sig ne "RGDB") {
            croak "Invalid RGDB block signature at offset ",
                sprintf("0x%x\n", $offset_to_rgdb_block),
                hexdump($rgdb_header, $offset_to_rgdb_block);
        }

        if ($rgkn_block_num == $rgdb_block_num) {
            # found the RGDB block
            $self->_look_up_entry_in_rgdb_block($offset_to_rgdb_block,
                                                $rgdb_block_size);
            return;
        }
        else {
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

    die "unexpected error: undefined regfile" if !defined($regfile);
    die "unexpected error: undefined rgkn_key_id" if !defined($rgkn_key_id);
    die "unexpected error: undefined rgkn_block_num" if !defined($rgkn_block_num);

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
            croak "Could not read RGDB entry for key at offset ",
                sprintf("0x%x\n", $offset_to_rgdb_entry);
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
                croak "Could not read RGDB entry name for key at offset ",
                    sprintf("0x%x\n", $offset_to_rgdb_entry);
            }

			$self->{_name} = $name;
            $self->{_name_length} = $name_length;
			$self->{_offset_to_rgdb_entry} = $offset_to_rgdb_entry;
			$self->{_num_values} = $num_values;

            return;
        }

        $offset_to_rgdb_entry += $rgdb_entry_size;
    }

    # Reached end of RGDB block without finding matching id
    croak "Could not find RGDB entry for key at offset ",
        sprintf("0x%x\n", $offset);
}

sub get_timestamp {
    return undef;
}

sub get_timestamp_as_string {
    return as_iso8601(undef);
}

sub print_summary {
    my $self = shift;

	print "$self->{_name} ";
	print "[subkeys=?] ";
	print "[values=$self->{_num_values}]\n";
}

sub print_debug {
    my $self = shift;

    print "$self->{_name} ";
    printf "[rgkn @ 0x%x",
        $self->{_offset};
    if (defined($self->{_offset_to_rgdb_entry})) {
        printf ",rgdb @ 0x%x] ", $self->{_offset_to_rgdb_entry};
    }
    else {
        print ",no rgdb] ";
    }
    printf "[p=0x%x,c=0x%x,n=0x%x] ",
            $self->{_offset_to_parent},
            $self->{_offset_to_first_child},
            $self->{_offset_to_next_sibling};
    printf "[id=0x%x,0x%x] ", $self->{_rgkn_key_id}, $self->{_rgkn_block_num};
	print "[k=?] ";
	print "[v=$self->{_num_values}]\n";

    # dump on-disk structures
    if (1) {
        sysseek($self->{_regfile}, $self->{_offset}, 0);
        sysread($self->{_regfile}, my $buffer, 28);
        print hexdump($buffer, $self->{_offset});
        if (defined($self->{_offset_to_rgdb_entry})) {
            sysseek($self->{_regfile}, $self->{_offset_to_rgdb_entry}, 0);
            sysread($self->{_regfile}, $buffer, 0x14 + $self->{_name_length});
            print hexdump($buffer, $self->{_offset_to_rgdb_entry});
        }
    }
}

sub get_list_of_subkeys {
    my $self = shift;

    my $path = $self->{_path};

    my @subkeys = ();

    my $regfile = $self->{_regfile};
    my $offset_to_first_child = $self->{_offset_to_first_child};

    if ($offset_to_first_child != 0xffffffff) {
        my $key = Parse::Win32Registry::Win95::Key->new($regfile,
                                                $offset_to_first_child, $path);
        push @subkeys, $key;
        while ($key->{_offset_to_next_sibling} != 0xffffffff) {
            $key = Parse::Win32Registry::Win95::Key->new($regfile,
                                       $key->{_offset_to_next_sibling}, $path);
            push @subkeys, $key;
        }
    }
    return @subkeys;
}

sub get_list_of_values {
	my $self = shift;

	my $regfile = $self->{_regfile};

    return () if $self->{_num_values} == 0;

    # The root key has an "invalid" id and block_num,
    # both being set to 0xffff, so it will not be possible to look up
    # the key name and value list in the RGDB blocks.
    # As the root key also has no values, it should be
    # filtered out by the initial check.
    # It is assumed that all other keys should have a valid name
    # and entry in the RGDB block.
	
	die "unexpected error: rgdb entry not looked up"
        if !defined($self->{_offset_to_rgdb_entry});

    my @values = ();

    # first RGDB value record starts after the end of the RGDB key record
    # length of a RGDB key record header is 0x14 
	my $offset_to_first_rgdb_value_entry
        = $self->{_offset_to_rgdb_entry} + 0x14 + length($self->{_name});
	sysseek($regfile, $offset_to_first_rgdb_value_entry, 0);

    my $offset_to_rgdb_value_entry = $offset_to_first_rgdb_value_entry;

	foreach (1..$self->{_num_values}) {
        my $value = Parse::Win32Registry::Win95::Value->new($regfile,
                                                  $offset_to_rgdb_value_entry);
        push @values, $value;

        $offset_to_rgdb_value_entry += $value->{_size_on_disk};
	}
    return @values;
}

1;
