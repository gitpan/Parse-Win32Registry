package Parse::Win32Registry::Win95::Entry;

use strict;
use warnings;

use base qw(Parse::Win32Registry::Entry);

use Carp;
use Parse::Win32Registry::Base qw(:all);
use Parse::Win32Registry::Win95::Key;

use constant RGKN_ENTRY_LENGTH => 28;

sub new {
    my $class = shift;
    my $regfile = shift;
    my $offset = shift;

    croak "Missing registry file" if !defined $regfile;
    croak "Missing offset" if !defined $offset;

    if (my $key = Parse::Win32Registry::Win95::Key->new($regfile, $offset)) {
        $key->regenerate_path;
        return $key;
    }

    my $self = {};
    $self->{_regfile} = $regfile;
    $self->{_offset} = $offset;
    $self->{_length} = RGKN_ENTRY_LENGTH;
    $self->{_allocated} = 0;
    $self->{_tag} = "rgkn";
    bless $self, $class;

    return $self;
}

sub as_string {
    my $self = shift;

    return "(rgkn entry)";
}

sub parse_info {
    my $self = shift;

    my $info = sprintf "0x%x,%d rgkn entry",
        $self->{_offset},
        $self->{_length};

    return $info;
}

1;
