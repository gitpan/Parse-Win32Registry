package Parse::Win32Registry::Win95::Value;

use strict;
use warnings;

use base qw(Parse::Win32Registry::Value);

use Carp;
use Encode;
use Parse::Win32Registry::Base qw(:all);

sub new {
    my $class = shift;
    my $regfile = shift;
    my $offset = shift; # offset to RGDB value entry
    my $parent_key_path = shift; # parent key path (for errors)

    die "unexpected error: undefined regfile" unless defined $regfile;
    die "unexpected error: undefined offset" unless defined $offset;

    # when errors are encountered
    my $whereabouts = (defined $parent_key_path)
                    ? " (a value of $parent_key_path)"
                    : "";

	# RGDB Value Entry
	# 0x00 dword = value type
	# 0x04
	# 0x08 word  = value name length
	# 0x0a word  = value data length
	# 0x0c       = value name [for name length bytes]
	#            + value data [for data length bytes]
    # Value type may just be a word, not a dword.
    # Following word appears to be zero.

	sysseek($regfile, $offset, 0);
    sysread($regfile, my $rgdb_value_entry, 12);
    if (!defined($rgdb_value_entry) || length($rgdb_value_entry) != 12) {
        log_error("Could not read RGDB entry for value at 0x%x%s",
            $offset, $whereabouts);
        return;
    }

    my ($type,
        $name_len,
        $data_len) = unpack("Vx4vv", $rgdb_value_entry);

    sysread($regfile, my $name, $name_len);
    if (!defined($name) || length($name) != $name_len) {
        log_error("Could not read RGDB entry name for value at 0x%x%s",
            $offset, $whereabouts);
        return;
    }

    sysread($regfile, my $data, $data_len);
    if (!defined($data) || length($data) != $data_len) {
        log_error("Could not read RGDB entry data for value at 0x%x%s",
            $offset, $whereabouts);
        return;
    }

    my $size_on_disk = length($rgdb_value_entry) + $name_len + $data_len;

    if ($type == REG_DWORD) {
        if ($data_len != 4) {
            $data = undef;
        }
    }

    my $self = {};
    $self->{_regfile} = $regfile;
    $self->{_offset} = $offset;
    $self->{_name} = $name;
    $self->{_type} = $type;
    $self->{_data} = $data;
    $self->{_size_on_disk} = $size_on_disk;
    bless $self, $class;

    return $self;
}

sub get_data {
    my $self = shift;

    my $type = $self->{_type};
    die "unexpected error: undefined type" if !defined($type);

    my $data = $self->{_data};
    
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
        # Snip off any terminating null.
        # Typically, REG_SZ values will not have a terminating null,
        # while REG_EXPAND_SZ values will have a terminating null
        my $last_char = substr($data, -1, 1);
        if (ord($last_char) == 0) {
            $data = substr($data, 0, length($data) - 1);
        }
    }
    elsif ($type == REG_MULTI_SZ) {
        my @s = unpack_string($data);
        pop @s if @s > 1 && $s[-1] eq ''; # drop trailing empty string
        return wantarray ? @s : join($", @s);
    }

    return $data;
}

sub as_regedit_export {
    my $self = shift;
    my $version = shift || 5;

    my $name = $self->get_name;
    my $s = $name eq '' ? '@=' : '"' . $name . '"=';

    my $type = $self->get_type;

    if ($type == REG_SZ) {
        $s .= '"' . $self->get_data . '"'; # get_data returns a utf8 string
        $s .= "\n";
    }
    elsif ($type == REG_BINARY) {
        $s .= 'hex:';
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
                 ? $self->{_data} # raw data
                 : encode("UCS-2LE", $self->{_data}); # ansi->unicode
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

    my $s = sprintf 'rgdb=0x%x "%s" type=%s (%s) data=%d bytes',
        $self->{_offset},
        $self->{_name},
        $self->get_type,
        $self->get_type_as_string,
        length($self->{_data});
}

sub as_hexdump {
    my $self = shift;
    my $regfile = $self->{_regfile};

    my $hexdump = '';

    sysseek($regfile, $self->{_offset}, 0);
    sysread($regfile, my $buffer, $self->{_size_on_disk});
    $hexdump .= hexdump($buffer, $self->{_offset});

    return $hexdump;
}

1;
