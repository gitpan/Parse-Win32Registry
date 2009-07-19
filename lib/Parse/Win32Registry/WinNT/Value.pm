package Parse::Win32Registry::WinNT::Value;

use strict;
use warnings;

use base qw(Parse::Win32Registry::Value);

use Carp;
use Encode;
use Parse::Win32Registry::Base qw(:all);

use constant OFFSET_TO_FIRST_HBIN => 0x1000;
use constant VK_HEADER_LENGTH => 0x18;

sub new {
    my $class = shift;
    my $regfile = shift;
    my $offset = shift; # offset to vk record relative to first hbin
    my $parent_key_path = shift; # parent key path (for errors)

    croak "Missing registry file" if !defined $regfile;
    croak "Missing offset" if !defined $offset;

    # when errors are encountered
    my $whereabouts = defined($parent_key_path)
                    ? " (a value of '$parent_key_path')"
                    : "";

    if (0) {
        printf("NEW VALUE at 0x%x%s\n", $offset, $whereabouts);
    }

    my $fh = $regfile->{_filehandle};
    croak "Missing filehandle" if !defined $fh;

    # 0x00 dword = value length (as negative number)
    # 0x04 word  = 'vk' signature
    # 0x06 word  = value name length
    # 0x08 dword = length of data (bit 31 set => data stored inline)
    # 0x0c dword = offset to data/inline data
    # 0x10 dword = type of data
    # 0x14 word  = flag (bit 0 set = name present, unset = default)
    # 0x16 word
    # 0x18       = value name [for name length bytes]

    # Extracted offsets are always relative to first HBIN

    sysseek($fh, $offset, 0);
    my $bytes_read = sysread($fh, my $vk_header, VK_HEADER_LENGTH);
    if ($bytes_read != VK_HEADER_LENGTH) {
        warnf("Could not read value at 0x%x%s", $offset, $whereabouts);
        return;
    }

    my ($length,
        $sig,
        $name_length,
        $data_length,
        $offset_to_data,
        $type,
        $name_present_flag,
        ) = unpack("Va2vVVVv", $vk_header);

    my $allocated = 0;
    if ($length > 0x7fffffff) {
        $allocated = 1;
        $length = (0xffffffff - $length) + 1;
    }
    # allocated should be true

    if ($sig ne "vk") {
        warnf("Invalid signature for value at 0x%x%s", $offset, $whereabouts);
        return;
    }

    my $name = "";
    if ($name_present_flag & 1) {
        $bytes_read = sysread($fh, $name, $name_length);
        if ($bytes_read != $name_length) {
            warnf("Could not read name for value at 0x%x%s",
                $offset, $whereabouts);
            return;
        }
    }

    my $data;

    # If the top bit of the data_length is set, then
    # the value is inline and stored in the offset to data field (at 0xc).
    my $data_inline = $data_length >> 31;
    if ($data_inline) {
        # REG_DWORDs are always inline, but I've also seen
        # REG_SZ, REG_BINARY, REG_EXPAND_SZ, and REG_NONE inline
        $data_length &= 0x7fffffff;
        if ($data_length > 4) {
            warnf("Invalid inline data length for value '%s' at 0x%x%s",
                $name, $offset, $whereabouts);
            $data = undef;
        }
        else {
            # unpack inline data from header
            $data = substr($vk_header, 0xc, $data_length);
        }
    }
    else {
        $offset_to_data += OFFSET_TO_FIRST_HBIN
            if $offset_to_data != 0xffffffff;

        sysseek($fh, $offset_to_data + 4, 0);
        $bytes_read = sysread($fh, $data, $data_length);
        if ($bytes_read != $data_length) {
            warnf("Could not read data at 0x%x for value '%s' at 0x%x%s",
                $offset_to_data, $name, $offset, $whereabouts);
            $data = undef;
        }
    }

    my $self = {};
    $self->{_regfile} = $regfile;
    $self->{_offset} = $offset;
    $self->{_length} = $length;
    $self->{_allocated} = $allocated;
    $self->{_tag} = $sig;
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

    my $type = $self->get_type;
    croak "Missing type" if !defined $type;

    my $data = $self->{_data};
    return if !defined $data;

    # apply decoding to appropriate data types
    if ($type == REG_DWORD) {
        if (length($data) == 4) {
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
        if (substr($data, -1, 1) eq "\x00") {
            chop $data;
        }
    }
    elsif ($type == REG_MULTI_SZ) {
        my @multi_sz = ();
        my $pos = 0;
        do {
            my ($str, $str_len) = unpack_unicode_string(substr($data, $pos));
            push @multi_sz, $str;
            $pos += $str_len;
        } while ($pos < length($data));
        # drop trailing empty string (caused by trailing null)
        pop @multi_sz if @multi_sz > 1 && $multi_sz[-1] eq '';
        return wantarray ? @multi_sz : join($", @multi_sz);
    }

    return $data;
}

sub as_regedit_export {
    my $self = shift;
    my $version = shift || 5;

    my $name = $self->get_name;
    my $export = $name eq "" ? "@=" : '"' . $name . '"=';

    my $type = $self->get_type;

    if ($type == REG_SZ) {
        $export .= '"' . $self->get_data . '"';
    }
    elsif ($type == REG_BINARY) {
        $export .= "hex:";
        $export .= format_octets($self->get_data, length($export));
    }
    elsif ($type == REG_DWORD) {
        my $data = $self->get_data;
        $export .= defined($data)
            ? sprintf("dword:%08x", $data)
            : "dword:";
    }
    elsif ($type == REG_EXPAND_SZ || $type == REG_MULTI_SZ) {
        my $data = $version == 4
                 ? encode("ascii", $self->{_data}) # unicode->ascii
                 : $self->{_data}; # raw data
        $export .= sprintf("hex(%x):", $type);
        $export .= format_octets($data, length($export));
    }
    else {
        my $data = $self->get_data;
        $export .= sprintf("hex(%x):", $type);
        $export .= format_octets($data, length($export));
    }
    $export .= "\n";
    return $export;
}

sub parse_info {
    my $self = shift;

    my $info = sprintf '0x%x,%d,%d vk "%s" type=%d (%s)',
        $self->{_offset},
        $self->{_allocated},
        $self->{_length},
        $self->{_name},
        $self->{_type},
        $self->get_type_as_string;
    if ($self->{_data_inline}) {
        $info .= sprintf ' data=inline,%d bytes "%s"',
            $self->{_data_length},
            $self->get_data_as_string;
    }
    else {
        $info .= sprintf ' | data=0x%x,%d bytes',
            $self->{_offset_to_data},
            $self->{_data_length};
    }
    return $info;
}

1;
