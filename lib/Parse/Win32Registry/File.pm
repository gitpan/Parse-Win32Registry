package Parse::Win32Registry::File;

use strict;
use warnings;

sub get_filename {
    my $self = shift;

    return $self->{_filename};
}

sub get_length {
    my $self = shift;

    return $self->{_length};
}

# method provided for backwards compatibility
sub move_to_first_entry {
    my $self = shift;

    $self->{_entry_iter} = undef;
}

# method provided for backwards compatibility
sub get_next_entry {
    my $self = shift;

    my $entry_iter = $self->{_entry_iter};
    if (!defined $entry_iter) {
        $self->{_entry_iter} = $entry_iter = $self->get_entry_iterator;
    }
    return $entry_iter->();
}

1;
