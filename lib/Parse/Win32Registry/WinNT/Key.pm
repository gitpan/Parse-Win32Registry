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

    croak "undefined regfile" unless defined $regfile;
    croak "undefined offset" unless defined $offset;

    my $self = {};
    $self->{_regfile} = $regfile;
    $self->{_offset} = $offset;
    
    sysseek($regfile, OFFSET_TO_FIRST_HBIN + $offset, 0);
    sysread($regfile, my $nk_header, 0x50);

    # 0x00 dword = size (as negative number)
    # 0x04 word  = 'nk' signature
    # 0x06 word  = 2c 00 for root node, 20 00 for other nodes
    # 0x08 qword = timestamp
    # 0x18 dword = number of subkeys
    # 0x20 dword = offset to subkey list (lf, lh, ri, li)
    # 0x28 dword = number of values
    # 0x2c dword = offset to value list
    # 0x4c word  = key name length
    # 0x4e word  = class length
    # 0x50       = key name [for name length bytes]

    my $size = (0xffffffff - unpack("V", $nk_header)) + 1;
    
    my $sig = unpack("a2", substr($nk_header, 0x4, 2));
    if ($sig ne "nk") {
        croak sprintf("invalid nk signature [$sig] at 0x%x+0x4\n",
            OFFSET_TO_FIRST_HBIN + $offset),
            hexdump($nk_header, OFFSET_TO_FIRST_HBIN + $offset);
    }

    my $nk_node_type = unpack("v", substr($nk_header, 0x6, 2));
    if ($nk_node_type == 0x2c) {
        $self->{_is_root_key} = 1;
    }
    elsif ($nk_node_type == 0x20) {
        $self->{_is_root_key} = 0;
    }
    else {
        croak sprintf("invalid nk node type [0x%x] at 0x%x+0x6\n",
            $nk_node_type,
            OFFSET_TO_FIRST_HBIN + $offset),
            hexdump($nk_header, OFFSET_TO_FIRST_HBIN + $offset);
    }
    
    my $timestamp = unpack("a8", substr($nk_header, 0x8, 8));
    $self->{_timestamp} = decode_win32_filetime($timestamp);

    my $name_length = unpack("v", substr($nk_header, 0x4c, 4));

    sysread($regfile, my $name, $name_length);
    $self->{_name} = $name;

    my $num_subkeys = unpack("V", substr($nk_header, 0x18, 4));
    my $num_values  = unpack("V", substr($nk_header, 0x28, 4));
    $self->{_num_subkeys} = $num_subkeys;
    $self->{_num_values} = $num_values;

    if ($num_subkeys > 0) {
        $self->{_offset_to_subkey_list}
            = unpack("V", substr($nk_header, 0x20, 4));
    }
    if ($num_values > 0) {
        $self->{_offset_to_value_list}
            = unpack("V", substr($nk_header, 0x2c, 4));
    }

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

	printf "%s @ 0x%x ",
        $self->{_name},
        OFFSET_TO_FIRST_HBIN + $self->{_offset};
    print "[r=$self->{_is_root_key}] ";
	print "[$self->{_num_subkeys}] ";
	print "[$self->{_num_values}] ";
    print "[$self->{_timestamp}]\n";
}

sub get_offsets_to_subkeys {
    my $self = shift;
    my $offset = shift; # only used for recursive lists such as 'ri'
    
    my $regfile = $self->{_regfile};

    my $offset_to_subkey_list = $offset || $self->{_offset_to_subkey_list};

    sysseek($regfile, OFFSET_TO_FIRST_HBIN + $offset_to_subkey_list, 0);
    sysread($regfile, my $subkey_list_header, 8);

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

    my ($size, $sig, $num_entries) = unpack("Va2v", $subkey_list_header);
    $size = (0xffffffff - $size) + 1;

    if ($sig eq "lf") {
        sysread($regfile, my $lf_record, 2 * 4 * $num_entries);
        for (my $i = 0; $i < $num_entries; $i++) {
            my ($offset, $str) = unpack("VV", substr($lf_record, 8 * $i, 8));
            push @offsets_to_subkeys, $offset;
        }
    }
    elsif ($sig eq "lh") {
        sysread($regfile, my $lh_record, 2 * 4 * $num_entries);
        for (my $i = 0; $i < $num_entries; $i++) {
            my ($offset, $hash) = unpack("VV", substr($lh_record, 8 * $i, 8));
            push @offsets_to_subkeys, $offset;
        }
    }
    elsif ($sig eq "ri") {
        sysread($regfile, my $ri_record, 4 * $num_entries);
        foreach my $offset (unpack("V$num_entries", $ri_record)) {
            push @offsets_to_subkeys,
                 @{ $self->get_offsets_to_subkeys($offset) };
        }
    }
    elsif ($sig eq "li") {
        sysread($regfile, my $li_record, 4 * $num_entries);
        foreach my $offset (unpack("V$num_entries", $li_record)) {
            push @offsets_to_subkeys, $offset;
        }
    }
    else {
        croak sprintf("invalid subkey list signature [$sig] at 0x%x+0x4\n",
            OFFSET_TO_FIRST_HBIN + $offset_to_subkey_list),
            hexdump($subkey_list_header,
            OFFSET_TO_FIRST_HBIN + $offset_to_subkey_list);
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
    croak "num_values is zero" if $num_values == 0; # sanity check

    my @offsets_to_values = ();
    
    # 0x00 dword = size (as negative number)
    # 0x04 dword = 1st offset
    # 0x08 dword = 2nd offset
    # ...

    sysseek($regfile, OFFSET_TO_FIRST_HBIN + $offset_to_value_list, 0);
    sysread($regfile, my $value_list, 0x4 + $num_values * 4);

    my $size = (0xffffffff - unpack("V", $value_list)) + 1;

    foreach my $offset (unpack("V$num_values", substr($value_list, 4))) {
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
