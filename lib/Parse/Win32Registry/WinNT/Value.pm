package Parse::Win32Registry::WinNT::Value;

use strict;
use warnings;

use base qw(Parse::Win32Registry::Value);

use Carp;
use Encode;
use Parse::Win32Registry::Base qw(:all);

use constant OFFSET_TO_FIRST_HBIN => 0x1000;

sub new {
    my $class = shift;
    my $regfile = shift;
    my $offset = shift; # offset to vk record relative to first hbin
    my $parent_key_path = shift; # parent key path (for errors)

    die "unexpected error: undefined regfile" unless defined $regfile;
    die "unexpected error: undefined offset" unless defined $offset;

    # when errors are encountered
    my $whereabouts = (defined $parent_key_path)
                    ? " (a value of $parent_key_path)"
                    : "";

    # 0x00 dword = size (as negative number)
    # 0x04 word  = 'vk' signature
    # 0x06 word  = value name length
    # 0x08 dword = length of data (bit 31 set => data stored inline)
    # 0x0c dword = offset of data
    # 0x10 dword = type of data
    # 0x14 word  = flag (bit 0 set = name present, unset = default)
    # 0x16 word
    # 0x18       = value name [for name length bytes]

    # Extracted offsets are always relative to first HBIN
    
    sysseek($regfile, $offset, 0);
    sysread($regfile, my $vk_header, 0x18);
    if (!defined($vk_header) || length($vk_header) != 0x18) {
        log_error("Could not read value at 0x%x%s", $offset, $whereabouts);
        return;
    }

    my ($size,
        $sig,
        $name_length,
        $data_length,
        $offset_to_data,
        $type,
        $name_present_flag,
        ) = unpack("Va2vVVVv", $vk_header);

    $offset_to_data += OFFSET_TO_FIRST_HBIN
        if $offset_to_data != 0xffffffff;

    if ($sig ne "vk") {
        log_error("Invalid value signature at 0x%x%s", $offset, $whereabouts);
        return;
    }

    my $name = "";
    if ($name_present_flag & 1) {
        sysread($regfile, $name, $name_length);
        if (!defined($name) || length($name) != $name_length) {
            log_error("Could not read value name at 0x%x%s", 
                $offset, $whereabouts);
            return;
        }
    }

    # If the top bit of the data_length is set, then
    # the value is inline and stored in the offset field (at 0xc).
    my $data;
    my $data_inline;
    if ($data_length & 0x80000000) {
        $data_inline = 1;
        # REG_DWORDs are always inline, but I've also seen
        # REG_SZ, REG_BINARY, REG_EXPAND_SZ, and REG_NONE inline
        $data_length &= 0x7fffffff;
        if ($data_length > 4) {
            log_error("Invalid inline data length for value '%s' at 0x%x%s", 
                $name, $offset, $whereabouts);
            $data = undef;
        }
        else {
            $data = substr($vk_header, 0xc, $data_length);
        }
    }
    else {
        $data_inline = 0;
        # add 4 to skip the initial size dword
        sysseek($regfile, $offset_to_data + 4, 0);
        sysread($regfile, $data, $data_length);
        if (!defined($data) || length($data) != $data_length) {
            log_error("Could not read data at 0x%x for value '%s' at 0x%x%s",
                $offset_to_data, $name, $offset, $whereabouts);
            return;
        }
    }

    if ($type == REG_DWORD) {
        if ($data_length != 4) {
            # a length of 0 is invalid for a DWORD value, but it does occur...
            $data = undef;
        }
    }

    my $self = {};
    $self->{_regfile} = $regfile;
    $self->{_offset} = $offset;
    $self->{_name} = $name;
    $self->{_type} = $type;
    $self->{_data} = $data;
    $self->{_data_length} = $data_length;
    $self->{_data_inline} = $data_inline;
    $self->{_offset_to_data} = $offset_to_data;
    bless $self, $class;

    return $self;
}

sub get_data {
    my $self = shift;

    my $type = $self->{_type};
    die "unexpected error: undefined type" if !defined($type);

    my $data = $self->{_data};
    return if !defined $data;

    my $data_length = $self->{_data_length};

    # apply decoding to appropriate data types
    if ($type == REG_DWORD) {
        if ($data_length == 4) {
            $data = unpack("V", $data);
        }
        else {
            # incorrect length for dword data
            $data = undef;
        }
    }
    elsif ($type == REG_SZ || $type == REG_EXPAND_SZ) {
        # handle unicode encoding 
        $data = decode("UCS-2LE", $data);

        # snip off any terminating null
        my $last_char = substr($data, -1, 1);
        if (ord($last_char) == 0) {
            $data = substr($data, 0, length($data) - 1);
        }
    }
    elsif ($type == REG_MULTI_SZ) {
        my @s = unpack_unicode_string($data);
        pop @s if @s > 1 && $s[-1] eq ''; # drop trailing empty string
        return wantarray ? @s : join($", @s);
    }

    return $data;
}

sub as_regedit_export {
    my $self = shift;
    my $version = shift || 5;

    my $name = $self->get_name;
    my $s = $name eq "" ? "@=" : '"' . $name . '"=';

    my $type = $self->get_type;

    if ($type == REG_SZ) {
        $s .= '"' . $self->get_data . '"';
        $s .= "\n";
    }
    elsif ($type == REG_BINARY) {
        $s .= "hex:";
        $s .= formatted_octets($self->get_data, length($s));
    }
    elsif ($type == REG_DWORD) {
        my $data = $self->get_data;
        $s .= defined($data)
            ? sprintf("dword:%08x", $data)
            : "dword:";
        $s .= "\n";
    }
    elsif ($type == REG_EXPAND_SZ || $type == REG_MULTI_SZ) {
        my $data = $version == 4
                 ? encode("ascii", $self->{_data}) # unicode->ascii
                 : $self->{_data}; # raw data
        $s .= sprintf("hex(%x):", $type);
        $s .= formatted_octets($data, length($s));
    }
    else {
        my $data = $self->get_data;
        $s .= sprintf("hex(%x):", $type);
        $s .= formatted_octets($data, length($s));
    }
    return $s;
}

sub parse_info {
    my $self = shift;
    my $verbose = shift;

    my $s = sprintf 'vk=0x%x "%s" type=%d (%s)',
        $self->{_offset},
        $self->{_name},
        $self->get_type,
        $self->get_type_as_string;

    if ($self->{_data_inline}) {
        $s .= sprintf ' data=inline,%d bytes "%s"',
            $self->{_data_length},
            $self->get_data_as_string;
    }
    else {
        $s .= sprintf ' | data=0x%x,%d bytes',
            $self->{_offset_to_data},
            $self->{_data_length};
    }
}

sub as_hexdump {
    my $self = shift;
    my $regfile = $self->{_regfile};

    my $hexdump = '';

    sysseek($regfile, $self->{_offset}, 0);
    sysread($regfile, my $buffer, 0x18 + length($self->{_name}));
    $hexdump .= hexdump($buffer, $self->{_offset});

    if (!$self->{_data_inline}) {
        sysseek($regfile, $self->{_offset_to_data}, 0);
        sysread($regfile, my $buffer, 0x4 + length($self->{_data}));
        $hexdump .= hexdump($buffer, $self->{_offset_to_data});
    }

    return $hexdump;
}


1;
