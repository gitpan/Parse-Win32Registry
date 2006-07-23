package Parse::Win32Registry;

use strict;
use warnings;

our $VERSION = '0.20';

# Exports have to be defined in a BEGIN { } so that any modules used
# by this module that in turn use this module will see them.
BEGIN {
    our @EXPORT = qw();
    our @EXPORT_OK = qw(
        decode_win32_filetime
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
use POSIX qw(strftime);

use Parse::Win32Registry::Win95;
use Parse::Win32Registry::WinNT;

sub new {
    my $class = shift;
    my $filename = shift or croak "no filename specified";

    open my $regfile, $filename or croak "unable to open $filename: $!";
    sysread($regfile, my $sig, 4);
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
        croak "not a registry file";
    }
}

# Thanks to Dan Sully's Audio::WMA for this
sub decode_win32_filetime {
    my $packed_filetime = shift;
    croak "invalid filetime length" if length($packed_filetime) != 8;
	my ($low, $high) = unpack('VV', $packed_filetime);
	my $filetime = $high * 2 ** 32 + $low;
    my $time = int(($filetime - 116444736000000000) / 10000000);
    return strftime("%Y-%m-%dT%H:%M:%SZ", gmtime $time);
    #return 0 if ($time < 0);
    #return 0x7fffffff if ($time > 0x7fffffff);
    #return $time;
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

The module provides an object-oriented interface to the keys and values
in a registry file. Registry files are structured as trees of keys,
with each key containing further subkeys or values.
Both Windows 95 and Windows NT based registry files are supported.

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

=item $registry = Parse::Win32Registry->new( "filename" );

Creates a new Registry object for the specified registry file.

=item $root_key = $registry->get_root_key;

Returns the root Key object of the registry file.

=back

=head2 Key Object Methods

=over 4

=item $key->get_name

Returns the name of the key. The root key of a Windows 95 Registry
does not have a name; this is returned as an empty string.

=item $key->get_subkey( "key name" )

Returns a Key object for the specified subkey name.
If a key with that name does not exist, nothing will be returned.

You can specify a path to a subkey by separating keys
using the path separator '\\'. For example:

    $key->get_subkey("Software\\Microsoft\\Windows")

A path is always relative to the current key.
If any key in the path does not exist, nothing will be returned.

=item $key->get_value( "value name" )

Returns a Value object for the specified value name.
If a value with that name does not exist, nothing will be returned.

=item $key->get_list_of_subkeys

Returns a list of Key objects representing the subkeys of the
current key. If a key has no subkeys, an empty list will be returned.

=item $key->get_list_of_values

Returns a list of Value objects representing the values of the
current key. If a key has no values, an empty list will be returned.

=item $key->print_summary

Prints the name, number of subkeys, and number of values for the key.

Windows NT based registry keys know how many subkeys and values they have,
while Windows 95 based registry keys only know how many values they have.

=back

=head2 Value Object Methods

=over 4

=item $value->get_name

Returns the name of the value. In both Windows 95 and Windows NT based
registry files you can get values without a name.

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

REG_SZ, REG_EXPAND_SZ, and REG_MULTI_SZ values
will be returned directly from Windows 95 based registry files
or converted from Unicode (UCS-2LE) for Windows NT based registry files.
Any terminating null characters will be removed
from REG_SZ and REG_EXPAND_SZ values.
To extract the component strings of a REG_MULTI_SZ value, you will need to
use the built-in split function to separate on null characters.

REG_DWORD values are unpacked and returned as integers.

undef will be returned for REG_DWORD values that do not have any data.
For all other types, zero-length data is considered valid.

All other types are returned as strings of binary data.

=item $value->get_data_as_string

Returns the data for a value, making it safe for printed output.

REG_SZ and REG_EXPAND_SZ values will be returned directly from get_data,
REG_MULTI_SZ values will have their component strings prefixed by
indices to more clearly show the number of elements, and
REG_DWORD values will be returned as integers formatted as hex numbers;
all other value types will be returned as a string of hex octets.

"(no data)" will be returned for REG_DWORD values that do not have any data,
instead of the undef returned by get_data.

=item $value->print_summary

Prints the name, type, and data for the value.

"(Default)" will be displayed for those values that do not have names.

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

=head1 ACKNOWLEDGEMENTS

This would not have been possible without the work of those people who have
analysed and documented the structure of Windows Registry files, namely:
the WINE Project (see misc/registry.c in older releases),
the Samba Project (see utils/editreg.c and utils/profiles.c),
the oft-referenced B.D. (for WinReg.txt),
and Petter Nordahl-Hagen (see chntpw's ntreg.h).

=head1 AUTHOR

James Macfarlane, E<lt>jmacfarla@cpan.orgE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006 by James Macfarlane

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

THIS PACKAGE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION,
THE IMPLIED WARRANTIES OF MERCHANTIBILITY AND FITNESS
FOR A PARTICULAR PURPOSE.

=cut
