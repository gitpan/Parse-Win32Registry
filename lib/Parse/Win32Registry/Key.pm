package Parse::Win32Registry::Key;

use strict;
use warnings;

use Carp;

sub get_name {
    my $self = shift;

    # the root key of a windows 95 registry has no defined name
    # but this should be set to "" when created
    die "unexpected error: undefined name" if !defined($self->{_name});

    return $self->{_name};
}

sub get_path {
    my $self = shift;

    die "unexpected error: undefined path" if !defined($self->{_key_path});

    return $self->{_key_path};
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
    
    # check for definedness in case key name is '' or '0'
    croak "No subkey name specified for get_subkey" if !defined($subkey_path);

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

    # check for definedness in case value name is '' or '0'
    croak "No value name specified for get_value" if !defined($value_name);

    foreach my $value ($self->get_list_of_values) {
        if (uc $value_name eq uc $value->{_name}) {
            return $value;
        }
    }
    return undef;
}

sub as_regedit_export {
    my $self = shift;

    return "[" . $self->{_key_path} . "]\n";
}

sub regenerate_path {
    my $self = shift;

    # find root
    my $key = $self;
    my @key_names = ($key->get_name);
    while (!$key->is_root) {
        $key = $key->get_parent;
        if (!defined($key)) {
            unshift @key_names, "(Invalid Parent Key)";
            last;
        }
        unshift @key_names, $key->get_name;
    }

    my $key_path = join("\\", @key_names);
    $self->{_key_path} = $key_path;
    return $key_path;
}

sub get_value_data {
    my $self = shift;
    my $value_name = shift;

    if (my $value = $self->get_value($value_name)) {
        return $value->get_data;
    }
    return;
}

sub get_mru_list_of_values {
    my $self = shift;

    my @values = ();

    if (my $mrulist = $self->get_value('MRUList')) {
        foreach my $ch (split(//, $mrulist->get_data)) {
            if (my $value = $self->get_value($ch)) {
                push @values, $value;
            }
        }
    }
    elsif (my $mrulistex = $self->get_value('MRUListEx')) {
        foreach my $item (unpack("V*", $mrulistex->get_data)) {
            last if $item == 0xffffffff;
            if (my $value = $self->get_value($item)) {
                push @values, $value;
            }
        }
    }
    return @values;
}

1;
