package Parse::Win32Registry::Base;

use strict;
use warnings;

use base qw(Exporter);

use Carp;
use Encode;
use Time::Local qw(timegm);

our @EXPORT_OK = qw(
    iso8601
    hexdump
    log_error
    unpack_string
    unpack_unicode_string
    unpack_windows_time
    formatted_octets
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

our %EXPORT_TAGS = (
    all => [@EXPORT_OK],
);

use constant REG_NONE => 0;
use constant REG_SZ => 1;
use constant REG_EXPAND_SZ => 2;
use constant REG_BINARY => 3;
use constant REG_DWORD => 4;
use constant REG_DWORD_BIG_ENDIAN => 5;
use constant REG_LINK => 6;
use constant REG_MULTI_SZ => 7;
use constant REG_RESOURCE_LIST => 8;
use constant REG_FULL_RESOURCE_DESCRIPTOR => 9;
use constant REG_RESOURCE_REQUIREMENTS_LIST => 10;
use constant REG_QWORD => 11;

our $WARNINGS = 1;

sub log_error {
    my $message = shift;
    warn sprintf "$message\n", @_ if $WARNINGS;
}

sub unpack_string {
    my $data = shift;

    chop $data if substr($data, -1, 1) eq "\0";

    if (length($data) == 0) {
        return wantarray ? ('') : '';
    }

    if (wantarray) {
        my @strings = split /\0/, $data, -1;
        return @strings;
    }
    else {
        my ($string) = split /\0/, $data, 2;
        return $string;
    }
}

sub unpack_unicode_string {
    my $data = shift;

    my @strings = ();

    chop $data if length($data) % 2 == 1;

    if (length($data) == 0) {
        return wantarray ? ('') : '';
    }

    my $pos = 0;
    my $start = 0;
    foreach my $v (unpack("v*", $data)) {
        $pos += 2;
        if ($v == 0) {
            my $string = decode("UCS-2LE", 
                                substr($data, $start, $pos-$start-2));
            push @strings, $string;
            $start = $pos;
            last unless wantarray; # quit, if we only want one string
        }
    }
    if ($start != $pos) { # there was no terminating null
        my $string = decode("UCS-2LE", substr($data, $start));
        push @strings, $string;
    }
    return wantarray ? @strings : $strings[0];
}

sub unpack_windows_time {
    my $data = shift;

    croak "Invalid filetime size (should be at least 8 bytes)"
        if length($data) < 8;

    my @t = ();

	foreach (my $start = 0; (length($data)-$start)>=8; $start += 8) {
        # The conversion uses real numbers
        # as 32-bit perl does not provide 64-bit integers.
        # The equation can be found in several places on the Net.
        # My thanks go to Dan Sully for Audio::WMA's _fileTimeToUnixTime
        # which shows a perl implementation of it.
        my ($low, $high) = unpack('VV', substr($data, $start, 8));
        my $filetime = $high * 2 ** 32 + $low;
        my $epoch_time = int(($filetime - 116444736000000000) / 10000000);

        # adjust the UNIX epoch time to the local OS's epoch time
        # (see perlport's Time and Date section)
        my $epoch_offset = timegm(0, 0, 0, 1, 0, 70);
        $epoch_time += $epoch_offset;

        if ($epoch_time < 0) {
            $epoch_time = undef;
        }

        push @t, $epoch_time;
    }

    return wantarray ? @t : $t[0];
}

sub iso8601 {
    my $time = shift;

    # check if we have been passed undef (i.e. an invalid date)
    if (!defined($time)) {
        return "(undefined)";
    }

    # On Windows, gmtime will return undef if $time < 0 or > 0x7fffffff
    if ($time < 0 || $time > 0x7fffffff) {
        return "(undefined)";
    }
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday) = gmtime $time;

    # The final 'Z' indicates UTC ("zero meridian")
    return sprintf "%04d-%02d-%02dT%02d:%02d:%02dZ",
        1900+$year, 1+$mon, $mday, $hour, $min, $sec;
}

sub hexdump {
    my $data = shift;
    my $pos = shift || 0; # starting point for the displayed position

    return "" if !defined($data);

    my $output = "";

    for (my $i = 0; $i < length($data); $i += 16) {
        $output .= sprintf "%8x  ", $i + $pos;

        my $row_length = 16;
        $row_length = length($data) - $i if $i + 16 > length($data);
        for (my $j = 0; $j < $row_length; $j++) {
            my $ch = substr($data, $i + $j, 1);
            $output .= sprintf "%02x ", ord $ch;
            if ($j % 4 == 3) { $output .= " "; } # dword gaps
        }
        for (my $j = $row_length; $j < 16; $j++) {
            $output .= "   ";
            if ($j % 4 == 3) { $output .= " "; } # dword gaps
        }

        for (my $j = 0; $j < $row_length; $j++) {
            my $ch = substr($data, $i + $j, 1);

            if (ord $ch >= 32 && ord $ch <= 126) {
                $output .= "$ch";
            } else {
                $output .= ".";
            }
        }

        $output .= "\n"; # end of row
    }
    return $output;
}

sub formatted_octets {
    my $data = shift; # packed binary data to append as hex
    my $col = shift || 0; # starting column, e.g. length of initial string

    return "" if !defined($data);

    my @data = unpack("C*", $data);

    my $output = "";

    for (my $i = 0; $i < @data; $i++) {
        if ($col > 76) { # insert line break at column 76
            $output .= "\\\n  ";
            $col = 2;
        }

        $output .= sprintf "%02x", $data[$i];
        $col += 2;

        if ($i < @data - 1) {
            $output .= ",";
            $col++;
        }
        
    }
    $output .= "\n";
    return $output;
}

1;
