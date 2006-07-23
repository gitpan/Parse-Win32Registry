package Parse::Win32Registry::Value;

use strict;
use warnings;

use Carp;

use Parse::Win32Registry qw(:REG_);

sub get_name {
    my $self = shift;

    return $self->{_name};
}

sub get_type {
    my $self = shift;

    return $self->{_type};
}

sub get_type_as_string {
    my $self = shift;

    my @types = qw(
        REG_NONE
        REG_SZ
        REG_EXPAND_SZ
        REG_BINARY
        REG_DWORD
        REG_DWORD_BIG_ENDIAN
        REG_LINK
        REG_MULTI_SZ
        REG_RESOURCE_LIST
        REG_FULL_RESOURCE_DESCRIPTOR
        REG_RESOURCE_REQUIREMENTS_LIST
        REG_QWORD
    );
    if (my $type_as_string = $types[$self->{_type}]) {
        return $type_as_string;
    }
    else {
        # The SAM contains values with unrecognised types
        return "[type=$self->{_type}]";
    }
}

sub get_data_as_string {
    my $self = shift;

    my $type = $self->get_type;
    my $data = $self->get_data;
    if (!defined($data)) {
        return "(no data)";
    }
    elsif ($type == REG_SZ || $type == REG_EXPAND_SZ) {
        return $data;
    }
    elsif ($type == REG_MULTI_SZ) {
        my @data = split("\x00", $data);
        $data = "";
        foreach (my $i = 0; $i < @data; $i++) {
            $data .= "($i) " . $data[$i] . " ";
        }
        return $data;
    }
    elsif ($type == REG_DWORD) {
        return sprintf "0x%08x", $data;
    }
    else {
        return join(" ", map { sprintf("%02x", $_) } unpack("C*", $data));
    }
}

1;

