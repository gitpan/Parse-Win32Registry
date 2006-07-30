package Parse::Win32Registry::WinNT::Key;

use strict;
use warnings;

use base qw(Parse::Win32Registry::Key);

use Parse::Win32Registry qw(decode_win32_filetime hexdump);
use Parse::Win32Registry::WinNT::Value;

use Carp;

use constant OFFSET_TO_FIRST_HBIN => 0x1000;

sub new {
    my $class = shift;
    my $regfile = shift;
    my $offset = shift; # offset to nk record relative to first hbin

    die "internal error: undefined regfile" if !defined $regfile;
    die "internal error: undefined offset" if !defined $offset;

    my $self = {};
    $self->{_regfile} = $regfile;
    $self->{_offset} = $offset;
    
    sysseek($regfile, OFFSET_TO_FIRST_HBIN + $offset, 0);
    sysread($regfile, my $nk_header, 0x50);
    if (!defined($nk_header) || length($nk_header) != 0x50) {
        croak "Could not read key",
            sprintf(" at offset 0x%x\n", OFFSET_TO_FIRST_HBIN + $offset);
    }

    # 0x00 dword = size (as negative number)
    # 0x04 word  = 'nk' signature
    # 0x06 word  = 2c 00 for root node, 20 00 for other nodes
    # 0x08 qword = timestamp
    # 0x14 dword = offset to parent
    # 0x18 dword = number of subkeys
    # 0x20 dword = offset to subkey list (lf, lh, ri, li)
    # 0x28 dword = number of values
    # 0x2c dword = offset to value list
    # 0x4c word  = key name length
    # 0x4e word  = class length
    # 0x50       = key name [for name length bytes]

    my ($size,
        $sig,
        $node_type,
        $timestamp,
        $offset_to_parent,
        $num_subkeys,
        $offset_to_subkey_list,
        $num_values,
        $offset_to_value_list,
        $name_length,
        ) = unpack("Va2va8x4VVx4Vx4VVx28v", $nk_header);

    #$size = (0xffffffff - $size) + 1;
    
    if ($sig ne "nk") {
        croak "Invalid key signature",
            sprintf(" at offset 0x%x\n",  + OFFSET_TO_FIRST_HBIN + $offset),
            hexdump($nk_header, OFFSET_TO_FIRST_HBIN + $offset);
    }

    if ($node_type == 0x2c) {
        $self->{_is_root_key} = 1;
    }
    elsif ($node_type == 0x20) {
        $self->{_is_root_key} = 0;
    }
    else {
        croak "Invalid key node type",
            sprintf(" at offset 0x%x\n",  + OFFSET_TO_FIRST_HBIN + $offset),
            hexdump($nk_header, OFFSET_TO_FIRST_HBIN + $offset);
    }
    
    $self->{_offset_to_parent} = $offset_to_parent;
    $self->{_num_subkeys} = $num_subkeys;
    $self->{_offset_to_subkey_list} = $offset_to_subkey_list;
    $self->{_num_values} = $num_values;
    $self->{_offset_to_value_list} = $offset_to_value_list;

    $self->{_timestamp} = decode_win32_filetime($timestamp);

    sysread($regfile, my $name, $name_length);
    if (!defined($name) || length($name) != $name_length) {
        croak "Could not read key name",
            sprintf(" at offset 0x%x\n", OFFSET_TO_FIRST_HBIN + $offset);
    }

    $self->{_name} = $name;

    bless $self, $class;
    return $self;
}

sub print_summary {
    my $self = shift;

    print "$self->{_name} ";
    print "[keys=$self->{_num_subkeys}] ";
    print "[values=$self->{_num_values}]\n";
}

sub print_debug {
    my $self = shift;

    print "$self->{_name} ";

	printf "[nk @ 0x%x] ", OFFSET_TO_FIRST_HBIN + $self->{_offset};
    print "[r=$self->{_is_root_key}] ";
    printf "[p=0x%x] ", OFFSET_TO_FIRST_HBIN + $self->{_offset_to_parent};
	printf "[k=%d,0x%x] ",
        $self->{_num_subkeys},
        ($self->{_offset_to_subkey_list} == 0xffffffff)
        ? $self->{_offset_to_subkey_list}
        : (OFFSET_TO_FIRST_HBIN + $self->{_offset_to_subkey_list});
	printf "[v=%d,0x%x] ",
        $self->{_num_values},
        ($self->{_offset_to_value_list} == 0xffffffff)
        ? $self->{_offset_to_value_list}
        : (OFFSET_TO_FIRST_HBIN + $self->{_offset_to_value_list});
    print "[$self->{_timestamp}]\n";

    # dump on-disk structures
    if (1) {
        my $regfile = $self->{_regfile};
        sysseek($regfile, OFFSET_TO_FIRST_HBIN + $self->{_offset}, 0);
        sysread($regfile, my $buffer, 0x50 + length($self->{_name}));
        print hexdump($buffer, OFFSET_TO_FIRST_HBIN + $self->{_offset});
    }        

    # dump offset lists
    if (1) {
        my $regfile = $self->{_regfile};
        my $num_subkeys = $self->{_num_subkeys};
        my $num_values = $self->{_num_values};
        if ($num_subkeys > 0) {
            print "\tsubkey list:\n";
            my $offset_to_subkey_list = $self->{_offset_to_subkey_list};
            sysseek($regfile,
                OFFSET_TO_FIRST_HBIN + $offset_to_subkey_list, 0);
            sysread($regfile, my $subkey_list, 8 + 4 * $num_subkeys);
            my $sig = unpack("x4a2", $subkey_list);
            if ($sig eq "lf" || $sig eq "lh") {
                sysseek($regfile,
                    OFFSET_TO_FIRST_HBIN + $offset_to_subkey_list, 0);
                sysread($regfile, $subkey_list, 8 + 8 * $num_subkeys);
            }
            print hexdump($subkey_list,
                OFFSET_TO_FIRST_HBIN + $offset_to_subkey_list);

            my $offsets_to_subkeys_ref = $self->get_offsets_to_subkeys;
            foreach my $offset_to_subkey (@{$offsets_to_subkeys_ref}) {
                printf "\t=> subkey @ 0x%x\n",
                    OFFSET_TO_FIRST_HBIN + $offset_to_subkey;
            }

        }
        if ($num_values > 0) {
            print "\tvalue list:\n";
            my $offset_to_value_list = $self->{_offset_to_value_list};
            sysseek($regfile,
                OFFSET_TO_FIRST_HBIN + $offset_to_value_list, 0);
            sysread($regfile, my $buffer, 0x4 + 4 * $num_values);
            print hexdump($buffer,
                OFFSET_TO_FIRST_HBIN + $offset_to_value_list);

            my $offsets_to_values_ref = $self->get_offsets_to_values;
            foreach my $offset_to_value (@{$offsets_to_values_ref}) {
                printf "\t=> value @ 0x%x\n",
                    OFFSET_TO_FIRST_HBIN + $offset_to_value;
            }
        }
    }
}

sub get_offsets_to_subkeys {
    my $self = shift;
    my $offset = shift; # only used for recursive lists such as 'ri'
    
    my $regfile = $self->{_regfile};

    my $offset_to_subkey_list = $offset || $self->{_offset_to_subkey_list};

    sysseek($regfile, OFFSET_TO_FIRST_HBIN + $offset_to_subkey_list, 0);
    sysread($regfile, my $subkey_list_header, 8);
    if (!defined($subkey_list_header) || length($subkey_list_header) != 8) {
        croak "Could not read subkey list header at offset ",
            sprintf("0x%x\n", OFFSET_TO_FIRST_HBIN + $offset_to_subkey_list);
    }

    # 0x00 dword = size (as negative number)
    # 0x04 word  = 'lf' signature
    # 0x06 word  = number of entries
    # 0x08 dword = offset to 1st subkey
    # 0x0c dword = first four characters of the key name
    # 0x10 dword = offset to 2nd subkey
    # 0x14 dword = first four characters of the key name
    # ...

    # 0x00 dword = size (as negative number)
    # 0x04 word  = 'lh' signature
    # 0x06 word  = number of entries
    # 0x08 dword = offset to 1st subkey
    # 0x0c dword = hash of the key name
    # 0x10 dword = offset to 2nd subkey
    # 0x14 dword = hash of the key name
    # ...

    # 0x00 dword = size (as negative number)
    # 0x04 word  = 'ri' signature
    # 0x06 word  = number of entries in ri list
    # 0x08 dword = offset to 1st lf/lh/li list
    # 0x0c dword = offset to 2nd lf/lh/li list
    # 0x10 dword = offset to 3rd lf/lh/li list
    # ...

    # 0x00 dword = size (as negative number)
    # 0x04 word  = 'li' signature
    # 0x06 word  = number of entries in li list
    # 0x08 dword = offset to 1st subkey
    # 0x0c dword = offset to 2nd subkey
    # ...
    
    my @offsets_to_subkeys = ();

    my ($size,
        $sig,
        $num_entries,
        ) = unpack("Va2v", $subkey_list_header);
    
    $size = (0xffffffff - $size) + 1;

    my $subkey_list_length;
    if ($sig eq "lf" || $sig eq "lh") {
        $subkey_list_length = 2 * 4 * $num_entries;
    }
    elsif ($sig eq "ri" || $sig eq "li") {
        $subkey_list_length = 4 * $num_entries;
    }
    else {
        croak "Invalid subkey list signature at offset ",
            sprintf("0x%x\n", OFFSET_TO_FIRST_HBIN + $offset_to_subkey_list),
            hexdump($subkey_list_header,
                OFFSET_TO_FIRST_HBIN + $offset_to_subkey_list);
    }

    sysread($regfile, my $subkey_list, $subkey_list_length);
    if (!defined($subkey_list) || length($subkey_list) != $subkey_list_length) {
        croak "Could not read subkey list at offset ",
            sprintf("0x%x\n", OFFSET_TO_FIRST_HBIN + $offset_to_subkey_list);
    }

    if ($sig eq "lf") {
        for (my $i = 0; $i < $num_entries; $i++) {
            my ($offset, $str) = unpack("VV", substr($subkey_list, 8 * $i, 8));
            push @offsets_to_subkeys, $offset;
        }
    }
    elsif ($sig eq "lh") {
        for (my $i = 0; $i < $num_entries; $i++) {
            my ($offset, $hash) = unpack("VV", substr($subkey_list, 8 * $i, 8));
            push @offsets_to_subkeys, $offset;
        }
    }
    elsif ($sig eq "ri") {
        foreach my $offset (unpack("V$num_entries", $subkey_list)) {
            push @offsets_to_subkeys,
                 @{ $self->get_offsets_to_subkeys($offset) };
        }
    }
    elsif ($sig eq "li") {
        foreach my $offset (unpack("V$num_entries", $subkey_list)) {
            push @offsets_to_subkeys, $offset;
        }
    }

    return \@offsets_to_subkeys;
}

sub get_list_of_subkeys {
    my $self = shift;

    my $regfile = $self->{_regfile};

    my @subkeys = ();

    if ($self->{_num_subkeys} > 0) {
        my $offsets_to_subkeys_ref = $self->get_offsets_to_subkeys;

        foreach my $offset_to_subkey (@{$offsets_to_subkeys_ref}) {
            my $subkey = Parse::Win32Registry::WinNT::Key->new($regfile,
                                                     $offset_to_subkey);
            push @subkeys, $subkey;
        }
    }

    return @subkeys;
}

sub get_offsets_to_values {
    my $self = shift;
    
    my $regfile = $self->{_regfile};
    my $offset_to_value_list = $self->{_offset_to_value_list};
    
    my $num_values = $self->{_num_values};
    die "internal error: num_values is zero" if $num_values == 0;

    my @offsets_to_values = ();
    
    # 0x00 dword = size (as negative number)
    # 0x04 dword = 1st offset
    # 0x08 dword = 2nd offset
    # ...

    sysseek($regfile, OFFSET_TO_FIRST_HBIN + $offset_to_value_list, 0);
    my $value_list_length = 0x4 + $num_values * 4;
    sysread($regfile, my $value_list, $value_list_length);
    if (!defined($value_list) || length($value_list) != $value_list_length) {
        croak "Could not read value list at offset ",
            sprintf("0x%x\n", OFFSET_TO_FIRST_HBIN + $offset_to_value_list);
    }

    my $size = (0xffffffff - unpack("V", $value_list)) + 1;

    foreach my $offset (unpack("x4V$num_values", $value_list)) {
        push @offsets_to_values, $offset;
    }
    
    return \@offsets_to_values;
}

sub get_list_of_values {
    my $self = shift;

    my $regfile = $self->{_regfile};

    my @values = ();

    if ($self->{_num_values} > 0) {
        my $offsets_to_values_ref = $self->get_offsets_to_values;

        foreach my $offset_to_value (@{$offsets_to_values_ref}) {
            my $value = Parse::Win32Registry::WinNT::Value->new($regfile,
                                                      $offset_to_value);
            push @values, $value;
        }
    }

    return @values;
}

1;
