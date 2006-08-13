package Parse::Win32Registry;

use strict;
use warnings;

our $VERSION = '0.23';

# Exports have to be defined in a BEGIN { } so that any modules used
# by this module that in turn use this module will see them.
BEGIN {
    our @EXPORT = qw();
    our @EXPORT_OK = qw(
        decode_win32_filetime
        as_iso8601
        hexdump
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
        REG_ => [qw(
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
        )],
    );
}

use base qw(Exporter);

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

use Carp;
use Time::Local qw(timegm);

use Parse::Win32Registry::Win95;
use Parse::Win32Registry::WinNT;

sub new {
    my $class = shift;
    my $filename = shift or croak "No filename specified";

    open my $regfile, "<", $filename or croak "Unable to open '$filename': $!";
    sysread($regfile, my $sig, 4);
    if (!defined($sig) || length($sig) != 4) {
        croak "Could not read registry file header\n";
    }
    close $regfile;

    if ($sig eq "CREG") {
        # attempt to parse this as a Windows 95 Registry File
        return Parse::Win32Registry::Win95->new($filename);
    }
    elsif ($sig eq "regf") {
        # attempt to parse this as a Windows NT Registry File
        return Parse::Win32Registry::WinNT->new($filename);
    }
    else {
        croak "Not a registry file\n";
    }
}

# Thanks to Dan Sully's Audio::WMA for this
sub decode_win32_filetime {
    my $packed_filetime = shift;
    die "unexpected error: invalid filetime length"
        if length($packed_filetime) != 8;
	my ($low, $high) = unpack('VV', $packed_filetime);
	my $filetime = $high * 2 ** 32 + $low;
    my $epoch_time = int(($filetime - 116444736000000000) / 10000000);

    # adjust the UNIX epoch time to the local OS's epoch time
    # (see perlport's Time and Date section)
    my $offset = timegm(0, 0, 0, 1, 0, 70);
    $epoch_time += $offset;

    if ($epoch_time < 0) {
        $epoch_time = undef;
    }

    return $epoch_time;
}

sub as_iso8601
{
    my $time = shift;

    # check if we have been passed undef (i.e. an invalid date)
    if (!defined($time)) {
        return "(undefined)";
    }

    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday) = gmtime $time;

    # The final 'Z' indicates UTC ("zero meridian")
    return sprintf "%04d-%02d-%02dT%02d:%02d:%02dZ",
        1900+$year, 1+$mon, $mday, $hour, $min, $sec;
}

sub hexdump
{
    my $data = shift;
    my $pos = shift || 0; # adjust the display relative to pos

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

1;

__END__

=head1 NAME

Parse::Win32Registry - Parse Windows Registry Files

=head1 SYNOPSIS

    use strict;
    use Parse::Win32Registry qw( :REG_ );

    my $filename = shift or die "Filename?";

    my $registry = Parse::Win32Registry->new($filename);
    my $root_key = $registry->get_root_key;

    my $software_key = $root_key->get_subkey(".DEFAULT\\Software")
                    || $root_key->get_subkey("Software");

    if (!defined($software_key)) {
        die "Could not locate the Software key\n";
    }

    my $key_name = "Microsoft\\Windows\\CurrentVersion\\Explorer";

    print "\nDisplaying $key_name (1):\n";
    if (my $key = $software_key->get_subkey($key_name)) {
        print $key->get_name, "\n";
        foreach my $value ($key->get_list_of_values) {
            my $value_name = $value->get_name || "(Default)";
            print "$value_name = ";
            my $value_type = $value->get_type;
            if ($value_type == REG_DWORD ||
                $value_type == REG_SZ ||
                $value_type == REG_EXPAND_SZ
            ) {
                print $value->get_data;
            }
            else {
                print "(not safe to print ", $value->get_type_as_string, ")";
            }
            print "\n";
        }
    }

    print "\nDisplaying $key_name (2):\n";
    if (my $key = $software_key->get_subkey($key_name)) {
        $key->print_summary;
        foreach my $value ($key->get_list_of_values) {
            $value->print_summary;
        }
    }

    sub traverse {
        my $key = shift;
        my $depth = shift || 0;

        print "  " x $depth;
        $key->print_summary;
        
        foreach my $subkey ($key->get_list_of_subkeys) {
            traverse($subkey, $depth + 1);
        }
    }

    print "\nDisplaying the registry tree from $key_name:\n";
    if (my $key = $software_key->get_subkey($key_name)) {
        traverse($key);
    }

=head1 DESCRIPTION

Parse::Win32Registry is a module for parsing Windows Registry files,
allowing you to read the keys and values of a registry file
without going through the Windows API.

It provides an object-oriented interface to the keys and values
in a registry file. Registry files are structured as trees of keys,
with each key containing further subkeys or values.

The module is intended to be cross-platform, and run on those platforms
where Perl will run.

It supports both Windows NT registry files (Windows NT, 2000, XP, 2003)
and Windows 95 registry files (Windows 95, 98, and Millennium Edition).

=head1 METHODS

Start by creating a Registry object from a valid registry file.
Use the Registry object's get_root_key method
to obtain the root key of that registry file.
This root key is your first Key object.
From this key, you can explore the Key and Value objects
that comprise the registry file using the methods described below.

Data is read directly from a registry file when a Key or Value object
is created, and discarded when the Key or Value object is destroyed.
This avoids any delay in parsing an entire registry file
before any Key or Value object is instantiated as it is anticipated that
generally code will only be extracting a subset of the keys and values
contained in a registry file.

=head2 Registry Object Methods

=over 4

=item $registry = Parse::Win32Registry->new( 'filename' );

Creates a new Registry object for the specified registry file.

=item $root_key = $registry->get_root_key;

Returns the root Key object of the registry file.

=back

=head2 Key Object Methods

=over 4

=item $key->get_name

Returns the name of the key. The root key of a Windows 95 Registry
does not have a name; this is returned as an empty string.

=item $key->get_subkey( 'key name' )

Returns a Key object for the specified subkey name.
If a key with that name does not exist, nothing will be returned.

You can specify a path to a subkey by separating keys
using the path separator '\\'. For example:

    $key->get_subkey( 'Software\\Microsoft\\Windows' )

A path is always relative to the current key.
If any key in the path does not exist, nothing will be returned.

=item $key->get_value( 'value name' )

Returns a Value object for the specified value name.
If a value with that name does not exist, nothing will be returned.

=item $key->get_list_of_subkeys

Returns a list of Key objects representing the subkeys of the
current key. If a key has no subkeys, an empty list will be returned.

=item $key->get_list_of_values

Returns a list of Value objects representing the values of the
current key. If a key has no values, an empty list will be returned.

=item $key->get_timestamp

Returns the timestamp for the key as a time value
suitable for passing to gmtime or localtime.

Only Windows NT registry keys have a timestamp;
Windows 95 registry keys do not.

Returns nothing if the date is out of range
or if called on a Windows 95 registry key.

=item $key->get_timestamp_as_string

Returns the timestamp as a ISO 8601 string,
for example, '2010-05-30T13:57:11Z'.
The Z indicates that the time is UTC ('Zero Meridian').

Returns the string '(undefined)' if the date is out of range
or if called on a Windows 95 registry key.

=item $key->print_summary

Prints the name, number of subkeys, and number of values for the key.
The timestamp will also be printed for Windows NT registry keys.

Windows NT registry keys know how many subkeys and values they have,
while Windows 95 registry keys only know how many values they have.

=back

=head2 Value Object Methods

=over 4

=item $value->get_name

Returns the name of the value.
In both Windows NT and Windows 95 based registry files
you can get values without a name.
This is returned as an empty string.

=item $value->get_type

Returns the integer representing the type of the data.
The constants for the value types can be imported from
the Parse::Win32Registry module with

    use Parse::Win32Registry qw( :REG_ );

=item $value->get_type_as_string

Returns the type of the data as a string instead of an integer constant,
making it more suitable for printed output.

=item $value->get_data

Returns the data for the value.

REG_SZ, REG_EXPAND_SZ, and REG_MULTI_SZ values will
be returned as strings.
The string data will be converted from Unicode (UCS-2LE) for Windows
NT based registry files.
Any terminating null characters will be removed from REG_SZ and
REG_EXPAND_SZ values.
To extract the component strings of a REG_MULTI_SZ value, you will need to
use the built-in split function to separate on null characters.

REG_DWORD values are unpacked and returned as integers.
undef will be returned for REG_DWORD values that contain invalid data.

All other types are returned as packed binary strings.

=item $value->get_data_as_string

Returns the data for a value, making it safe for printed output.

REG_SZ and REG_EXPAND_SZ values will be returned directly from get_data,
REG_MULTI_SZ values will have their component strings prefixed by
indices to more clearly show the number of elements, and
REG_DWORD values will be returned as integers formatted as hex numbers;
all other value types will be returned as a string of hex octets.

'(invalid data)' will be returned
for REG_DWORD values that contain invalid data,
instead of the undef returned by get_data.

'(no data)' will be returned if get_data returns an empty string.

=item $value->print_summary

Prints the name, type, and data for the value.

'(Default)' will be displayed for those values that do not have names.

=back

=head1 EXPORTS

On request, Parse::Win32Registry will export the registry type constants:

    use Parse::Win32Registry qw( :REG_ );

The :REG_ tag exports all of the following constants:

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

=head1 SCRIPTS

The dumpreg.pl script installed with the module can be used
to display the contents of a registry file.
The root key will be displayed unless a subkey is specified;
the path to a subkey is specified relative to the root key.
To display all keys beneath a key, instead of just the specified key,
use the --recurse option.

    dumpreg.pl <filename> [subkey] [-r] [-q] [-i] [-d]
        -r or --recurse     traverse all child keys from the root key
                            or the subkey specified
        -q or --quiet       do not display values
        -i or --indent      indent subkeys and values to reflect their
                            level in the registry tree
        -d or --debug       display debugging information about
                            subkeys and values

=head1 TROUBLESHOOTING

If you run into problems parsing a registry file, the error message
will probably begin with 'Could not read...' or 'Invalid...'.
Troubleshooting these messages is possible, but you will need to
be comfortable dealing with binary data and be prepared to refer
to the source for information on the internal registry data
structures.

'Could not read...' indicates that the code tried to read data that
did not exist; this is typically because the offset to that data was
invalid. To identify the source of the incorrect offset, you need to
work down through the registry tree, key by key, until you reach the
key or value that generates the error. Suspect the preceding key of
holding invalid data.

'Invalid...' indicates that the data was read successfully, but one of
the checks failed. This will occur either because the offset to that
data was invalid and points to the wrong place in the registry file
(which can be troubleshot as for 'Could not read...'), or because the
data being parsed is a new type of data structure. Unfortunately there
is no easy way to distinguish these without becoming familiar with
internal registry data structures. If you do think it is a new type of
data structure, let the author know.

The print_debug method can be used in place of the print_summary
to display additional information about keys and values.
This method has not been documented as it is not considered a stable
part of the public interface, and its output is largely
unintelligible to the unfamiliar. You may, however, find it useful.

=head1 ACKNOWLEDGEMENTS

This would not have been possible without the work of those people who have
analysed and documented the structure of Windows Registry files, namely:
the WINE Project (see misc/registry.c in older releases),
the Samba Project (see utils/editreg.c and utils/profiles.c),
the oft-referenced B.D. (for WinReg.txt),
and Petter Nordahl-Hagen (see chntpw's ntreg.h).

=head1 AUTHOR

James Macfarlane, E<lt>jmacfarla@cpan.orgE<gt>

If you have any requests or contributions, contact me.

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006 by James Macfarlane

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

THIS PACKAGE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION,
THE IMPLIED WARRANTIES OF MERCHANTIBILITY AND FITNESS
FOR A PARTICULAR PURPOSE.

=cut
