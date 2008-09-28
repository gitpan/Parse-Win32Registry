package Parse::Win32Registry::File;

use strict;
use warnings;

sub get_filename {
    my $self = shift;

    return $self->{_filename};
}

1;
