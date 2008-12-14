package Parse::Win32Registry::WinNT::Entry;

use strict;
use warnings;

use Carp;
use Parse::Win32Registry::Base qw(:all);
use Parse::Win32Registry::WinNT::Key;
use Parse::Win32Registry::WinNT::Value;

sub new {
    my $class = shift;
    my $regfile = shift or croak "No regfile specified";
    my $offset = shift or croak "No offset specified";

    sysseek($regfile, $offset, 0);
    sysread($regfile, my $entry_header, 8);
    if (!defined($entry_header) || length($entry_header) != 8) {
        return;
    }

    my ($size, $entry_type) = unpack("Va2", $entry_header);

    my $in_use = 0;
    if ($size > 0x7fffffff) {
        $in_use = 1;
        $size = (0xffffffff - $size) + 1;
    }

    if ($size <= 0) { # this entry is invalid
        return;
    }

    my $self = {
        _regfile => $regfile,
        _offset => $offset,
        _size => $size,
        _entry_type => $entry_type,
        _in_use => $in_use,
    };

    bless $self, $class;
    return $self;
}

sub get_offset {
    my $self = shift;

    return $self->{_offset};
}

sub get_entry_type {
    my $self = shift;

    return $self->{_entry_type};
}

sub is_in_use {
    my $self = shift;

    return $self->{_in_use};
}

sub as_string {
    my $self = shift;

    my $offset = $self->{_offset};
    my $regfile = $self->{_regfile};
    my $entry_type = $self->{_entry_type};
    my $size = $self->{_size};
    my $in_use = $self->{_in_use};

    $entry_type = ".." if $entry_type !~ /(nk|vk|lh|lf|li|ri|sk)/;

    my $string = sprintf "0x%06x %s %s ", $offset, $in_use, $entry_type;

    if ($entry_type eq "nk") {
        if (my $key = Parse::Win32Registry::WinNT::Key->new(
                      $regfile, $offset)
        ) {
            $key->regenerate_path;
            $string .= $key->as_string;
        }
    }
    elsif ($entry_type eq "vk") {
        if (my $value = Parse::Win32Registry::WinNT::Value->new(
                        $regfile, $offset)
        ) {
            $string .= $value->as_string;
        }
    }

    return $string;
}

sub parse_info {
    my $self = shift;

    my $offset = $self->{_offset};
    my $regfile = $self->{_regfile};
    my $entry_type = $self->{_entry_type};
    my $size = $self->{_size};
    my $in_use = $self->{_in_use};

    $entry_type = ".." if $entry_type !~ /(nk|vk|lh|lf|li|ri|sk)/;

    my $string = "";

    if ($entry_type eq "nk") {
        if (my $key = Parse::Win32Registry::WinNT::Key->new(
                      $regfile, $offset)
        ) {
            $string .= $key->parse_info;
        }
    }
    elsif ($entry_type eq "vk") {
        if (my $value = Parse::Win32Registry::WinNT::Value->new(
                        $regfile, $offset)
        ) {
            $string .= $value->parse_info;
        }
    }
    else {
        $string .= sprintf "%s=0x%x ", $entry_type, $offset;
    }

    return $string;
}

sub as_hexdump {
    my $self = shift;

    my $offset = $self->{_offset};
    my $size = $self->{_size};
    my $regfile = $self->{_regfile};
    my $in_use = $self->{_in_use};

    sysseek($regfile, $offset, 0);
    sysread($regfile, my $hbin_entry, $size);
    if (!defined($hbin_entry) || length($hbin_entry) != $size) {
        return;
    }
    else {
        if ($in_use) {
            return hexdump($hbin_entry, $offset);
        }
    }
}

1;
