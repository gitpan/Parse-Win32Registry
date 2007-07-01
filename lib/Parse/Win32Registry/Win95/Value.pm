package Parse::Win32Registry::Win95::Value;

use strict;
use warnings;

use base qw(Parse::Win32Registry::Value);

use Carp;

use Parse::Win32Registry qw(hexdump :REG_);

sub new {
    my $class = shift;

    my $regfile = shift;
    my $offset = shift; # offset to RGDB value entry

    my $self = {};

    $self->{_regfile} = $regfile;
    $self->{_offset} = $offset;

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
        croak "Could not read RGDB entry for value at offset ",
            sprintf("0x%x\n", $offset);
    }

    my ($value_type, $value_name_len, $value_data_len)
        = unpack("Vx4vv", $rgdb_value_entry);

    sysread($regfile, my $value_name, $value_name_len);
    if (!defined($value_name) || length($value_name) != $value_name_len) {
        croak "Could not read RGDB entry name for value at offset ",
            sprintf("0x%x\n", $offset);
    }

    sysread($regfile, my $value_data, $value_data_len);
    if (!defined($value_data) || length($value_data) != $value_data_len) {
        croak "Could not read RGDB entry data for value at offset ",
            sprintf("0x%x\n", $offset);
    }

    my $size_on_disk = length($rgdb_value_entry)
                     + $value_name_len
                     + $value_data_len;

    $self->{_name} = $value_name;
    $self->{_type} = $value_type;
    $self->{_data} = $value_data;

    $self->{_size_on_disk} = $size_on_disk;

    bless $self, $class;
    return $self;
}

sub get_data {
    my $self = shift;

    my $type = $self->{_type};
    die "unexpected error: undefined type" if !defined($type);

    my $data = $self->{_data};
    die "unexpected error: undefined data" if !defined($data);
    
    # apply decoding to appropriate data types
    if ($type == REG_DWORD) {
        if (length($data) == 4) {
            $data = unpack("V", $data);
        }
        else {
            #croak "incorrect length for dword data";
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

    return $data;
}

sub debugging_info {
    my $self = shift;

    my $s = sprintf "%s [rgdb @ 0x%x] ", $self->{_name}, $self->{_offset};

    $s .= "[type=" . $self->get_type . "] "
        . "(" . $self->get_type_as_string . ") "
        . "[len=" . length($self->{_data}) . "] "
        . $self->get_data_as_string . "\n";

    if (0) {
        $s .= hexdump($self->{_data});
    }

    # dump on-disk structure
    if (1) {
        sysseek($self->{_regfile}, $self->{_offset}, 0);
        sysread($self->{_regfile}, my $buffer, $self->{_size_on_disk});
        $s .= hexdump($buffer, $self->{_offset});
    }

    return $s;
}

1;
