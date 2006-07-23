package Parse::Win32Registry::Key;

use strict;
use warnings;

use Carp;

sub get_name {
    my $self = shift;

    # the root key of a windows 95 registry has no defined name
    # but this should be set to "" in new
    croak "name not defined" if !defined($self->{_name});

    return $self->{_name};
}

sub _lookup_subkey {
    my $self = shift;
    my $subkey_name = shift;

    foreach my $subkey ($self->get_list_of_subkeys) {
        if (uc $subkey_name eq uc $subkey->{_name}) {
            return $subkey;
        }
    }
    return;
}

sub get_subkey {
    my $self = shift;
    my $subkey_path = shift;

    my $key = $self;

    # current path component separator is '\' to match that used in Windows
    my @path_components = split(/\\/, $subkey_path);
    foreach my $component (@path_components) {
        if (my $subkey = $key->_lookup_subkey($component)) {
            $key = $subkey;
        }
        else {
            return;
        }
    }
    return $key;
}

sub get_value {
    my $self = shift;
    my $value_name = shift;

    foreach my $value ($self->get_list_of_values) {
        if (uc $value_name eq uc $value->{_name}) {
            return $value;
        }
    }
    return undef;
}

1;
