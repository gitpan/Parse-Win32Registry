package Parse::Win32Registry::Entry;

use strict;
use warnings;

use Carp;
use Parse::Win32Registry::Base qw(:all);

sub get_offset {
    my $self = shift;

    return $self->{_offset};
}

sub get_length {
    my $self = shift;

    return $self->{_length};
}

sub is_allocated {
    my $self = shift;

    return $self->{_allocated};
}

sub get_tag {
    my $self = shift;

    return $self->{_tag};
}

sub unparsed {
    my $self = shift;

    my $regfile = $self->{_regfile};
    croak "Missing registry file" if !defined $regfile;
    my $fh = $regfile->{_filehandle};
    croak "Missing filehandle" if !defined $fh;
    my $offset = $self->{_offset};
    croak "Missing offset" if !defined $offset;
    my $length = $self->{_length};
    croak "Missing length" if !defined $length;

    sysseek($fh, $offset, 0);
    my $bytes_read = sysread($fh, my $buffer, $length);
    if ($bytes_read == $length) {
        return hexdump($buffer, $offset);
    }
    else {
        return '';
    }
}

sub get_raw_bytes {
    my $self = shift;

    my $regfile = $self->{_regfile};
    croak "Missing registry file" if !defined $regfile;
    my $fh = $regfile->{_filehandle};
    croak "Missing filehandle" if !defined $fh;
    my $offset = $self->{_offset};
    croak "Missing offset" if !defined $offset;
    my $length = $self->{_length};
    croak "Missing length" if !defined $length;

    sysseek($fh, $offset, 0);
    my $bytes_read = sysread($fh, my $buffer, $length);
    if ($bytes_read == $length) {
        return $buffer;
    }
    else {
        return '';
    }
}

sub looks_like_key {
    return UNIVERSAL::isa($_[0], "Parse::Win32Registry::Key");
}

sub looks_like_value {
    return UNIVERSAL::isa($_[0], "Parse::Win32Registry::Value");
}

sub looks_like_security {
    return UNIVERSAL::isa($_[0], "Parse::Win32Registry::WinNT::Security");
}

1;
