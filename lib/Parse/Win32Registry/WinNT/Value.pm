package Parse::Win32Registry::WinNT::Value;

use strict;
use warnings;

use base qw(Parse::Win32Registry::Value);

use Carp;
use Encode; # for decoding unicode (ucs2le) strings

use Parse::Win32Registry qw(hexdump :REG_);

use constant OFFSET_TO_FIRST_HBIN => 0x1000;

sub new {
    my $class = shift;
    my $regfile = shift;
    my $offset = shift; # offset to vk record relative to first hbin

    die "internal error: undefined regfile" unless defined $regfile;
    die "internal error: undefined offset" unless defined $offset;

    my $self = {};
    $self->{_regfile} = $regfile;
    $self->{_offset} = $offset;

    sysseek($regfile, OFFSET_TO_FIRST_HBIN + $offset, 0);
    sysread($regfile, my $vk_header, 0x18);
    if (!defined($vk_header) || length($vk_header) != 0x18) {
        croak "Could not read value at offset ",
            sprintf("0x%x\n", OFFSET_TO_FIRST_HBIN + $offset);
    }

    # 0x00 dword = size (as negative number)
    # 0x04 word  = 'vk' signature
    # 0x06 word  = value name length
    # 0x08 dword = length of data (bit 31 set => data stored inline)
    # 0x0c dword = offset of data
    # 0x10 dword = type of data
    # 0x14 word  = flag (bit 0 set = name present, unset = default)
    # 0x16 word
    # 0x18       = value name [for name length bytes]

    my ($size,
        $sig,
        $name_length,
        $data_length,
        $offset_to_data,
        $type,
        $name_present_flag,
        ) = unpack("Va2vVVVv", $vk_header);

    if ($sig ne "vk") {
        croak "Invalid value signature at ",
            sprintf("0x%x\n", OFFSET_TO_FIRST_HBIN + $offset),
            hexdump($vk_header, OFFSET_TO_FIRST_HBIN + $offset);
    }

    my $name = "";
    if ($name_present_flag & 1) {
        sysread($regfile, $name, $name_length);
        if (!defined($name) || length($name) != $name_length) {
            croak "Could not read value name at offset ",
                sprintf("0x%x\n", OFFSET_TO_FIRST_HBIN + $offset);
        }
    }

    # If the top bit of the data_length is set, then
    # the value is inline and stored in the offset field (at 0xc).
    my $data;
    if ($data_length & 0x80000000) {
        # REG_DWORDs are always inline, but I've also seen
        # REG_SZ, REG_BINARY, REG_EXPAND_SZ, and REG_NONE inline
        $data_length &= 0x7fffffff;
        if ($data_length > 4) {
            croak "Invalid inline data length at offset",
                sprintf("0x%x\n", OFFSET_TO_FIRST_HBIN + $offset);
        }
        $data = substr($vk_header, 0xc, $data_length);
        $self->{_data_inline} = 1;
    } else {
        # add 4 to skip the initial size dword
        sysseek($regfile, OFFSET_TO_FIRST_HBIN + $offset_to_data + 4, 0);
        sysread($regfile, $data, $data_length);
        if (!defined($data) || length($data) != $data_length) {
            croak "Could not read data at offset ",
                sprintf("0x%x\n", OFFSET_TO_FIRST_HBIN + $offset_to_data);
        }
        $self->{_data_inline} = 0;
        $self->{_offset_to_data} = $offset_to_data;
    }
    die "internal error: undefined name" if !defined($name);
    die "internal error: undefined data" if !defined($data);

    # data integrity checks
    if ($data_length != length($data)) {
        die "internal error: data is not the expected length";
    }
    if ($type == REG_DWORD) {
        if ($data_length != 4) {
            # a length of 0 is invalid for a DWORD value, but it does occur...
        }
    }

    $self->{_offset} = $offset;
    $self->{_name} = $name;
    $self->{_type} = $type;
    $self->{_data} = $data;
    $self->{_data_length} = $data_length;

    bless $self, $class;
    return $self;
}

sub get_data {
    my $self = shift;

    my $type = $self->{_type};
    die "internal error: undefined type" if !defined($type);

    my $data = $self->{_data};
    my $data_length = $self->{_data_length};

    # apply decoding to appropriate data types
    if ($type == REG_SZ || $type == REG_EXPAND_SZ) {
        $data = decode("UCS-2LE", $data);

        # snip off any terminating null
        my $last_char = substr($data, -1, 1);
        if (ord($last_char) == 0) {
            $data = substr($data, 0, length($data) - 1);
        }
    }
    elsif ($type == REG_MULTI_SZ) {
        $data = decode("UCS-2LE", $data);
    }
    elsif ($type == REG_DWORD) {
        if ($data_length == 4) {
            $data = unpack("V", $data);
        }
        else {
            #croak "incorrect length for dword data";
            $data = undef;
        }
    }

    return $data;
}

sub print_summary {
    my $self = shift;

    my $name = $self->get_name || "(Default)";
    print $name;
    print " (", $self->get_type_as_string, ") = ";
    print $self->get_data_as_string;
    print "\n";
}

sub print_debug {
    my $self = shift;

    print $self->{_name} || "''";

    printf " [vk @ 0x%x,", OFFSET_TO_FIRST_HBIN + $self->{_offset};
    if ($self->{_data_inline}) {
        print "data inline";
    }
    else {
        printf "data @ 0x%x", OFFSET_TO_FIRST_HBIN + $self->{_offset_to_data};
    }
    print "] ";

    my $type = $self->get_type;
    my $type_as_string = $self->get_type_as_string;
    print "[type=$type] ($type_as_string) ";

    print "= ", $self->get_data_as_string, " ";
    print "[len=", length($self->{_data}), "]\n";

    print hexdump($self->{_data});

    # dump on-disk structures
    if (1) {
        my $regfile = $self->{_regfile};
        sysseek($regfile, OFFSET_TO_FIRST_HBIN + $self->{_offset}, 0);
        sysread($regfile, my $buffer, 0x18 + length($self->{_name}));
        print hexdump($buffer, OFFSET_TO_FIRST_HBIN + $self->{_offset});
        if (!$self->{_data_inline}) {
            sysseek($regfile,
                OFFSET_TO_FIRST_HBIN + $self->{_offset_to_data}, 0);
            sysread($regfile, my $buffer, 0x4 + length($self->{_data}));
            print hexdump($buffer,
                OFFSET_TO_FIRST_HBIN + $self->{_offset_to_data});
        }
    }        
}

1;
