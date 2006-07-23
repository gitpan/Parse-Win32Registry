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
    my ($value_type, $value_name_len, $value_data_len)
        = unpack("Vx4vv", $rgdb_value_entry);

    sysread($regfile, my $value_name, $value_name_len);
    sysread($regfile, my $value_data, $value_data_len);

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
    croak "undefined type" if !defined($type);

    my $data = $self->{_data};
    croak "undefined data" if !defined($data);
    
    # apply decoding to appropriate data types
    if ($type == REG_DWORD) {
        croak "incorrect length for dword data" if length($data) != 4;
        $data = unpack("V", $data);
    }
    elsif ($type == REG_EXPAND_SZ) {
        # snip off any terminating null
        my $last_char = substr($data, -1, 1);
        if (ord($last_char) == 0) {
            $data = substr($data, 0, length($data) - 1);
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
    printf " @ 0x%x ", $self->{_offset};

    my $type = $self->get_type;
    my $type_as_string = $self->get_type_as_string;
    print "[type=$type] ($type_as_string) ";

    print "= ", $self->get_data_as_string, " ";
    print "[len=", length($self->{_data}), "]\n";

    print hexdump($self->{_data});

    # dump on-disk structure
    if (0) {
        sysseek($self->{_regfile}, $self->{_offset}, 0);
        sysread($self->{_regfile}, my $buffer, $self->{_size_on_disk});
        print hexdump($buffer, $self->{_offset});
    }
}

1;
