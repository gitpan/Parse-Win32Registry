package Parse::Win32Registry;

use strict;
use warnings;

our $VERSION = '0.30';

use base qw(Exporter);

our @EXPORT_OK = qw(
    convert_filetime_to_epoch_time
    iso8601
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

require Parse::Win32Registry::Win95::File;
require Parse::Win32Registry::WinNT::File;

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
        return Parse::Win32Registry::Win95::File->new($filename);
    }
    elsif ($sig eq "regf") {
        # attempt to parse this as a Windows NT Registry File
        return Parse::Win32Registry::WinNT::File->new($filename);
    }
    else {
        croak "Not a registry file\n";
    }
}

# Thanks to Dan Sully's Audio::WMA for the _fileTimeToUnixTime function
# which was the original basis for this
sub convert_filetime_to_epoch_time {
    my $packed_filetime = shift;

    croak "Invalid filetime size (should be 8 bytes)"
        if length($packed_filetime) < 8;

	my ($low, $high) = unpack('VV', $packed_filetime);
	my $filetime = $high * 2 ** 32 + $low;
    my $epoch_time = int(($filetime - 116444736000000000) / 10000000);

    # adjust the UNIX epoch time to the local OS's epoch time
    # (see perlport's Time and Date section)
    my $epoch_offset = timegm(0, 0, 0, 1, 0, 70);
    $epoch_time += $epoch_offset;

    if ($epoch_time < 0) {
        $epoch_time = undef;
    }

    return $epoch_time;
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
    use Parse::Win32Registry qw(:REG_);

    my $filename = shift or die "Filename?";

    my $registry = Parse::Win32Registry->new($filename);
    my $root_key = $registry->get_root_key;

    # The following code works on USER.DAT or NTUSER.DAT files

    my $software_key = $root_key->get_subkey(".DEFAULT\\Software")
                    || $root_key->get_subkey("Software");

    if (defined($software_key)) {
        my @user_key_names = (
            "Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
            "Microsoft\\Windows\\CurrentVersion\\Run",
            "Microsoft\\Internet Explorer",
            "Microsoft\\Internet Explorer\\Main",
        );

        print_list_of_keys($software_key, @user_key_names);

        # This demonstrates how to use the decode function from the
        # Encode module to convert binary data into a Unicode string.
        # Encode has been in the Perl standard library since 5.8.
        use Encode;
        foreach my $version (qw(8.0 9.0 10.0 11.0)) {
            my $key_name = "Microsoft\\Office\\$version\\Common\\UserInfo";
            if (my $userinfo_key = $software_key->get_subkey($key_name)) {
                print "\n", $userinfo_key->as_string, "\n";
                foreach my $value_name ("UserName", "UserInitials", "Company") {
                    if (my $value = $userinfo_key->get_value($value_name)) {
                        print $value->as_string, "\n";
                        my $data = decode("UCS-2LE", $value->get_data);
                        print "$value_name is the unicode string '$data'\n";
                    }
                }
            }
        }
    }

    # The following code works on SYSTEM.DAT or SOFTWARE files

    my $software_key = $root_key->get_subkey("Software") || $root_key;

    if (defined($software_key)) {
        my @software_key_names = (
            "Microsoft\\Windows\\CurrentVersion",
            "Microsoft\\Windows NT\\CurrentVersion",
            "Microsoft\\Windows\\CurrentVersion\\Run",
            "Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
            "Microsoft\\Internet Explorer",
        );

        print_list_of_keys($software_key, @software_key_names);

        # This demonstrates how you can deal with a Unix date
        # found in a registry value
        my $key_name = "Microsoft\\Windows NT\\CurrentVersion";
        if (my $currentversion_key = $software_key->get_subkey($key_name)) {
            print "\n", $currentversion_key->as_string, "\n";
            if (my $value = $currentversion_key->get_value("InstallDate")) {
                print $value->as_string, "\n";
                my $data = $value->get_data;
                print "InstallDate was ", scalar gmtime $data, " GMT\n";
                print "InstallDate was ", scalar localtime $data, " Local\n";
            }
        }
    }

    # The following code works on SYSTEM.DAT or SYSTEM files

    my $system_key = $root_key->get_subkey("System") || $root_key;

    my $ccs_name = "CurrentControlSet"; # default for Win95
    if (my $key = $system_key->get_subkey("Select")) {
        my $current_value = $key->get_value("Current");
        $ccs_name = "ControlSet00" . $current_value->get_data;
        print "CurrentControlSet = $ccs_name\n";
    }

    my $ccs_key = $system_key->get_subkey($ccs_name);

    if (defined($ccs_key)) {
        my @system_key_names = (
            "Control\\ComputerName\\ComputerName",
            "Control\\TimeZoneInformation",
        );

        print_list_of_keys($ccs_key, @system_key_names);
    }

    # Given a starting key object and a list of subkey names
    # relative to the starting key, this function will print
    # out each subkey and its values
    sub print_list_of_keys {
        my ($start_key, @key_names) = @_;
        foreach my $key_name (@key_names) {
            if (my $key = $start_key->get_subkey($key_name)) {
                print "\n", $key->as_string, "\n";
                foreach my $value ($key->get_list_of_values) {
                    print $value->as_string, "\n";
                }
            }
        }
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

The root key of a registry file is not the same as one of the virtual
roots of the registry (HKEY_LOCAL_MACHINE, HKEY_USERS, etc) that you
may be familiar with from using tools such as REGEDIT.

=back

=head2 Key Object Methods

=over 4

=item $key->get_name

Returns the name of the key. The root key of a Windows 95 based
registry file does not have a name; this is returned as an empty
string.

=item $key->get_path

Returns the path to the key. This is relative to the root key of the
registry file, not a virtual root such as HKEY_LOCAL_MACHINE.

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
(the number of seconds since your computer's epoch)
suitable for passing to gmtime or localtime.

Only Windows NT registry keys have a timestamp.

Returns nothing if the date is out of range
or if called on a Windows 95 registry key.

=item $key->get_timestamp_as_string

Returns the timestamp as a ISO 8601 string,
for example, '2010-05-30T13:57:11Z'.
The Z indicates that the time is GMT ('Zero Meridian').

Returns the string '(undefined)' if the date is out of range
or if called on a Windows 95 registry key.

=item $key->as_string

Returns the path of the key as a string.
The timestamp will be appended for Windows NT registry keys.

=item $key->print_summary

Prints $key->as_string to standard output.

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

REG_DWORD values are unpacked and returned as unsigned integers.
undef will be returned for REG_DWORD values that contain invalid data.

All other types are returned as packed binary strings.

=item $value->get_data_as_string

Returns the data for a value, making it safe for printed output.

REG_SZ and REG_EXPAND_SZ values will be returned directly from get_data,
REG_MULTI_SZ values will have their component strings prefixed by
indices to more clearly show the number of elements, and
REG_DWORD values will be returned as a hexadecimal number followed
by its parenthesized decimal equivalent.
All other types of values will be returned as a string of hex octets.

'(invalid data)' will be returned
for REG_DWORD values that contain invalid data,
instead of the undef returned by get_data.

'(no data)' will be returned if get_data returns an empty string.

=item $value->as_string

Returns the name, type, and data for the value as a string,
safe for printed output.

'(Default)' will be displayed for those values that do not have names.

=item $value->print_summary

Prints $value->as_string to standard output.

=back

=head1 EXPORTS

=head2 Constants

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

=head2 Support Functions

Parse::Win32Registry will export the following support functions
on request:

=over 4

=item convert_filetime_to_epoch_time( $packed_filetime )

Returns the epoch time for the given Win32 FILETIME.
A Win32 FILETIME is a 64-bit integer
containing the number of 100-nanosecond intervals since January 1st, 1601
and can sometimes be found in Windows NT registry values.
It should be passed as 8 bytes of packed binary data.

undef will be returned if the date is earlier than your computer's epoch.
The epoch begins at January 1st, 1970 on Unix and Windows machines.

=item iso8601( $epoch_time )

Returns the ISO8601 string for the given $epoch_time,
for example, '2010-05-30T13:57:11Z'.

The string '(undefined)' will be returned if the epoch time is out of range.

=back

For example, if 'UpdateTime' is a REG_BINARY value that contains
a Win32 FILETIME, you can extract and convert it as follows:

    use Parse::Win32Registry qw( convert_filetime_to_epoch_time iso8601 );

    ...
    
    if (my $value = $key->get_value('UpdateTime')) {
        my $data = $value->get_data;
        my $update_time = convert_filetime_to_epoch_time($data);
        my $update_time_as_string = iso8601($update_time);
        print "UpdateTime = $update_time_as_string\n";
    }

=head1 SCRIPTS

=head2 regdump.pl

regdump.pl is used to display the keys and values of a registry file. 
You can use this to help develop your own scripts,
or as a command line tool for examining registry files.

Type regdump.pl on its own to see the help:

    regdump.pl <filename> [subkey] [-r] [-q]
        -r or --recurse     traverse all child keys from the root key
                            or the subkey specified
        -q or --quiet       do not display values

The contents of the root key will be displayed unless a subkey is
specified. Paths to subkeys are always specified relative to the root
key. By default, only the subkeys and values immediately underneath
the specified key will be displayed. To display all keys and values
beneath a key, use the -r or --recurse option.

For example, regdump.pl ntuser.dat might display the following:

    $$$PROTO.HIV  [2005-01-01T09:00:00Z]
    ..\AppEvents
    ..\Console
    ..\Control Panel
    ..\Environment
    ..\Identities
    ..\Keyboard Layout
    ..\Printers
    ..\Software
    ..\UNICODE Program Groups

From here, you can explore the subkeys to find those keys or values
you are interested in:

    regdump.pl ntuser.dat software
    regdump.pl ntuser.dat software\microsoft
    regdump.pl ntuser.dat software\microsoft\windows
    regdump.pl ntuser.dat software\microsoft\windows\currentversion
    ...

Remember to quote any subkey path that contains spaces:

    regdump.pl ntuser.dat "software\microsoft\windows nt\currentversion"

=head2 regfind.pl

regfind.pl is used to search the keys, values, or data
of a registry file for a matching string.

Type regfind.pl on its own to see the help:

    regfind.pl <filename> <search-string> [-k] [-v] [-d]
        -k or --key       search key names for a match
        -v or --value     search value names for a match
        -d or --data      search value data for a match

To search for the string "recent" in the names of any keys or values:

    regfind.pl ntuser.dat recent -kv

To search for the string "administrator" in the data of any values:

    regfind.pl ntuser.dat administrator -d

Search strings are not case-sensitive.

=head2 regdiff.pl

regdiff.pl is used to compare two registry files and identify the
differences between them.

Type regdiff.pl on its own to see the help:

    regdiff.pl <filename1> <filename2> [subkey] [-p] [-q]
        -p or --previous    show the previous key or value
                            (this is not normally shown)
        -q or --quiet       do not display values

When comparing Windows NT based registry files, regdiff.pl can
identify if a key has been updated by comparing timestamps.
When comparing Windows 95 based registry files, it needs to check all
its values to see if any have changed.

You can limit the comparison by specifying an initial subkey.

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

The debugging_info method can be used in place of the as_string method
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

Copyright (C) 2006,2007 by James Macfarlane

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

THIS PACKAGE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION,
THE IMPLIED WARRANTIES OF MERCHANTIBILITY AND FITNESS
FOR A PARTICULAR PURPOSE.

=cut
