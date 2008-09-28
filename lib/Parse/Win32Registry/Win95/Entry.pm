package Parse::Win32Registry::Win95::Entry;

use strict;
use warnings;

use Carp;
use Parse::Win32Registry::Base qw(:all);
use Parse::Win32Registry::Win95::Key;
use Parse::Win32Registry::Win95::Value;

sub new {
    my $class = shift;
    my $regfile = shift or croak "No regfile specified";
    my $offset = shift or croak "No offset specified";

    my $self = {
        _regfile => $regfile,
        _offset => $offset,
    };

    bless $self, $class;
    return $self;
}

sub get_offset {
    my $self = shift;

    return $self->{_offset};
}

sub as_string {
    my $self = shift;

    my $offset = $self->{_offset};
    my $regfile = $self->{_regfile};

    my $string = sprintf "0x%06x ", $offset;

    if (my $key = Parse::Win32Registry::Win95::Key->new($regfile, $offset)) {
        $key->regenerate_path;
        $string .= $key->as_string;
    }

    return $string;
}

sub parse_info {
    my $self = shift;

    my $offset = $self->{_offset};
    my $regfile = $self->{_regfile};

    my $string = "";

    if (my $key = Parse::Win32Registry::Win95::Key->new($regfile, $offset)) {
        $string .= $key->parse_info;
    }
    else {
        $string .= sprintf "rgkn=0x%x", $offset;
    }

    return $string;
}

sub as_hexdump {
    my $self = shift;

    my $offset = $self->{_offset};
    my $regfile = $self->{_regfile};

    sysseek($regfile, $offset, 0);
    sysread($regfile, my $rgkn_entry, 28);
    if (!defined($rgkn_entry) || length($rgkn_entry) != 28) {
        return;
    }
    else {
        return hexdump($rgkn_entry, $offset);
    }
}

1;
