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

    croak "undefined regfile" unless defined $regfile;
    croak "undefined offset" unless defined $offset;

    my $self = {};
    $self->{_regfile} = $regfile;
    $self->{_offset} = $offset;

    sysseek($regfile, OFFSET_TO_FIRST_HBIN + $offset, 0);
    sysread($regfile, my $vk_header, 0x18);

    croak sprintf("unable to read vk header at offset 0x%x",
        OFFSET_TO_FIRST_HBIN + $offset) if length($vk_header) != 0x18;

    # 0x00 dword = size (as negative number)
    # 0x04 word  = 'vk' signature
    # 0x06 word  = value name length
    # 0x08 dword = length of data (bit 31 set => data stored inline)
    # 0x0c dword = offset of data
    # 0x10 dword = type of data
    # 0x14 word  = flag (bit 0 set = name present, unset = default)
    # 0x16 word
    # 0x18       = value name [for name length bytes]

    my $sig = unpack("a2", substr($vk_header, 0x4, 2));
    if ($sig ne "vk") {
        croak sprintf("invalid vk signature [$sig] at 0x%x+0x4\n",
            OFFSET_TO_FIRST_HBIN + $offset),
            hexdump($vk_header, OFFSET_TO_FIRST_HBIN + $offset);
    }

    my $name_present_flag = unpack("v", substr($vk_header, 0x14, 2));

    my $name;
    if ($name_present_flag & 1) {
        my $name_length = unpack("v", substr($vk_header, 0x6, 2));
        sysread($regfile, $name, $name_length);
    }

    my $data_length = unpack("V", substr($vk_header, 0x8, 4));
    my $offset_to_data = unpack("V", substr($vk_header, 0xc, 4));
    my $type = unpack("V", substr($vk_header, 0x10, 4));

    # If the top bit of the data_length is set, then
    # the value is inline and stored in the offset field (at 0xc).
    my $data;
    if ($data_length & 0x80000000) {
        # REG_DWORDs are always inline, but I've also seen
        # REG_SZ, REG_BINARY, REG_EXPAND_SZ, and REG_NONE inline
        $data_length &= 0x7fffffff;
        $data = substr($vk_header, 0xc, $data_length);
    } else {
        # read the data from the file, skip 4 to ignore the initial [size] dword
        sysseek($regfile, OFFSET_TO_FIRST_HBIN + $offset_to_data + 4, 0);
        sysread($regfile, $data, $data_length);
    }
    croak "undefined data" if !defined($data);

    # data integrity checks
    if ($data_length != length($data)) {
        croak sprintf("data is not the expected length at offset 0x%X\n",
            OFFSET_TO_FIRST_HBIN + $offset),
            "should be $data_length, was actually ", length($data);
    }
    if ($type == REG_DWORD) {
        if ($data_length != 4 && $data_length != 0) {
            # actually, a length of 0 is invalid for a DWORD value,
            # but it does occur
            croak sprintf("unexpected data_length [$data_length] for REG_DWORD at 0x%x+0x8\n",
                OFFSET_TO_FIRST_HBIN + $offset),
                hexdump($vk_header, OFFSET_TO_FIRST_HBIN + $offset);
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
    croak "undefined type" if !defined($type);

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
        elsif ($data_length == 0) {
            $data = undef; # invalid DWORD value
        }
        else {
            croak "REG_DWORD data length != 4 for $self->{_name} value\n",
                "data length = $data_length\n",
                "length = ", length($self->{_data}), "\n",
                hexdump($data);
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

    my $name = $self->get_name || "(Default)";
    print $name;
    printf " @ 0x%x ", OFFSET_TO_FIRST_HBIN + $self->{_offset};

    my $type = $self->get_type;
    my $type_as_string = $self->get_type_as_string;
    print "[type=$type] ($type_as_string) ";

    print "= ", $self->get_data_as_string, " ";
    print "[len=$self->{_data_length}]\n";

    print hexdump($self->{_data});
}

1;
