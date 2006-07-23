package Parse::Win32Registry::Win95::Key;

use strict;
use warnings;

use base qw(Parse::Win32Registry::Key);

use Parse::Win32Registry qw(:REG_);
use Parse::Win32Registry::Win95::Value;

use Carp;

use constant OFFSET_TO_RGKN_BLOCK => 0x20;
use constant RGKN_ENTRY_SIZE => 28;

sub new {
    my $class = shift;
    my $regfile = shift;
    my $offset = shift; # offset to RGKN key entry from OFFSET_TO_RGKN_BLOCK

    croak "undefined regfile" unless defined $regfile;
    croak "undefined offset" unless defined $offset;

    my $self = {};
    $self->{_regfile} = $regfile;
    $self->{_offset} = $offset;

    # offset is a pointer to RGKN entry, relative to start of RGKN

    return if $offset == 0xffffffff;

    sysseek($regfile, OFFSET_TO_RGKN_BLOCK + $offset, 0);
    sysread($regfile, my $rgkn_entry, 28);

    croak sprintf("unable to read RGKN entry at offset 0x%x",
        OFFSET_TO_RGKN_BLOCK + $offset) if length($rgkn_entry) != 28;

    # RGKN Key Entry
    # 0x00 dword
    # 0x04 dword = hash (unpacked, but not used)
    # 0x08 dword
    # 0x0c dword = offset to parent RGKN entry
    # 0x10 dword = offset to first child RGKN entry
    # 0x14 dword = offset to next sibling RGKN entry
    # 0x18 word  = id of RGDB entry
    # 0x1a word  = number of RGDB block

    # Any offset of 0xffffffff marks the end of a list.
    # An id and block_num of 0xffff means the RGKN entry
    # has no RGDB entry. This occurs for the root key RGKN entry
    # (and presumably also for invalid RGKN entries).

    my ($hash,
        $offset_to_parent,
        $offset_to_first_child,
        $offset_to_next_sibling,
        $rgkn_key_id,
        $rgkn_block_num) = unpack("x4Vx4VVVvv", $rgkn_entry);

    $self->{_hash} = $hash;
    $self->{_offset_to_parent} = $offset_to_parent;
    $self->{_offset_to_first_child} = $offset_to_first_child;
    $self->{_offset_to_next_sibling} = $offset_to_next_sibling;
    $self->{_rgkn_key_id} = $rgkn_key_id;
    $self->{_rgkn_block_num} = $rgkn_block_num;

    bless $self, $class;

    # look up RGDB entry to determine the key's name and value list
	$self->_look_up_rgdb_entry;
	
    return $self;
}

sub _look_up_rgdb_entry {
	my $self = shift;

    my $regfile = $self->{_regfile};
    my $rgkn_key_id = $self->{_rgkn_key_id};
    my $rgkn_block_num = $self->{_rgkn_block_num};

    croak "undefined regfile" unless defined($regfile);
    croak "undefined rgkn_key_id" unless defined($rgkn_key_id);
    croak "undefined rgkn_block_num" unless defined($rgkn_block_num);

    # The root key has an id of 0xffff and a block_num of 0xffff
    # and this cannot be successfully looked up in the RGDB blocks.
    # So abandon the attempt. The fields _name, _offset_to_rgdb_entry,
    # and _num_values may be set to something other than undef.
    $self->{_name} = ""; # or "NONAME"?
    $self->{_num_values} = 0;
    return if $rgkn_key_id == 0xffff || $rgkn_block_num == 0xffff;

    # get offset to first RGDB block from CREG header
    sysseek($regfile, 0, 0);
    sysread($regfile, my $creg_header, 12);

    # start from the offset to the first RGDB block
    my $offset_to_rgdb_block = unpack("x8 V", $creg_header);

    # skip block_num RGDB blocks:
    foreach (0..$rgkn_block_num-1) {
        sysseek($regfile, $offset_to_rgdb_block, 0);

        # RGDB Block Header
        # 0x0 dword = 'RDGB' signature 
        # 0x4 dword = RGDB block size

        sysread($regfile, my $rgdb_header, 32);

        my ($sig, $rgdb_block_size) = unpack("a4V", $rgdb_header);
        if ($sig ne "RGDB") {
            croak sprintf("invalid RGDB block signature [%s] at offset 0x%x",
                $sig, $offset_to_rgdb_block);
        }

        $offset_to_rgdb_block += $rgdb_block_size;
    }

    # now find id in this RGDB block
    sysseek($regfile, $offset_to_rgdb_block, 0);
    sysread($regfile, my $rgdb_header, 32);

    my ($sig, $rgdb_block_size) = unpack("a4V", $rgdb_header);
    if ($sig ne "RGDB") {
        croak sprintf("invalid RGDB block signature [%s] at offset 0x%x",
            $sig, $offset_to_rgdb_block);
    }

    # The first record in the RGDB block
    # begins immediately after the RGDB header
    my $offset_to_rgdb_entry = $offset_to_rgdb_block + length($rgdb_header);

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

        sysread($regfile, my $rgdb_key_entry, 0x14);
        my ($rgdb_entry_size,
            $rgdb_key_id,
            $rgdb_block_num,
            $bytes_used,
            $name_length,
            $num_values) = unpack("VvvVvv", $rgdb_key_entry);

        if ($rgdb_key_id == $rgkn_key_id) {
            # found a match (id is checked, block_num is not)

            sysread($regfile, my $name, $name_length);

			$self->{_name} = $name;
            $self->{_name_length} = $name_length;
			$self->{_offset_to_rgdb_entry} = $offset_to_rgdb_entry;
			$self->{_num_values} = $num_values;

            return;
        }

        $offset_to_rgdb_entry += $rgdb_entry_size;
        sysseek($regfile, $offset_to_rgdb_entry, 0);
    }

	# If we reach here, we've failed to find the corresponding RGDB entry
	# for this registry key's RGKN entry.
	croak sprintf "could not find RGDB entry for [id=0x%x, block=0x%x]",
        $rgkn_key_id, $rgkn_block_num;
}

sub print_summary {
    my $self = shift;

	print "$self->{_name} ";
	print "[keys=?] ";
	print "[values=$self->{_num_values}]\n";
}

sub print_debug {
    my $self = shift;

    my $rgdb_entry_present
        = !($self->{_rgkn_key_id} == 0xffff
        && $self->{_rgkn_block_num} == 0xffff);
    printf "%s @ 0x%x,",
        $self->{_name},
        OFFSET_TO_RGKN_BLOCK + $self->{_offset};
    if ($rgdb_entry_present) {
        printf "0x%x ", $self->{_offset_to_rgdb_entry};
    }
    else {
        print "none ";
    }
    printf "[p=0x%x,c=0x%x,n=0x%x] ",
        $self->{_offset_to_parent},
        $self->{_offset_to_first_child},
        $self->{_offset_to_next_sibling};
    printf "[id=0x%x,0x%x] ", $self->{_rgkn_key_id}, $self->{_rgkn_block_num};
	print "[?] ";
	print "[$self->{_num_values}]\n";

    # dump on-disk structures
    if (0) {
        sysseek($self->{_regfile}, OFFSET_TO_RGKN_BLOCK + $self->{_offset}, 0);
        sysread($self->{_regfile}, my $buffer, 28);
        print hexdump($buffer, OFFSET_TO_RGKN_BLOCK + $self->{_offset});
        if ($rgdb_entry_present) {
            sysseek($self->{_regfile}, $self->{_offset_to_rgdb_entry}, 0);
            sysread($self->{_regfile}, $buffer, 0x14 + $self->{_name_length});
            print hexdump($buffer, $self->{_offset_to_rgdb_entry});
        }
    }
}

sub get_list_of_subkeys {
    my $self = shift;

    my @subkeys = ();

    my $regfile = $self->{_regfile};
    my $offset_to_first_child = $self->{_offset_to_first_child};

    if ($offset_to_first_child != 0xffffffff) {
        my $key = Parse::Win32Registry::Win95::Key->new($regfile,
                                                       $offset_to_first_child);
        push @subkeys, $key;
        while ($key->{_offset_to_next_sibling} != 0xffffffff) {
            $key = Parse::Win32Registry::Win95::Key->new($regfile,
                                              $key->{_offset_to_next_sibling});
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
	
	croak "rgdb entry not looked up"
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
