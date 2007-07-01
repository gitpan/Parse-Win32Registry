package Parse::Win32Registry::Key;

use strict;
use warnings;

use Carp;

sub get_name {
    my $self = shift;

    # the root key of a windows 95 registry has no defined name
    # but this should be set to "" in new
    die "unexpected error: undefined name" if !defined($self->{_name});

    return $self->{_name};
}

sub get_path {
    my $self = shift;

    die "unexpected error: undefined path" if !defined($self->{_path_list});

    return join("\\", @{$self->{_path_list}});
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
    
    if (!defined($subkey_path)) {
        croak "No subkey name specified";
    }

    my $key = $self;

    # Current path component separator is '\' to match that used in Windows.
    # split returns nothing if it is given an empty string,
    # and without a limit of -1 drops trailing empty fields.
    my @path_components = index($subkey_path, "\\") == -1
                        ? ($subkey_path)
                        : split(/\\/, $subkey_path, -1);
    foreach my $component (@path_components) {
        if (my $subkey = $key->_lookup_subkey($component)) {
            $key = $subkey;
        }
        else { # we can stop looking
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
