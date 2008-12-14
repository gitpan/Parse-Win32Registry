package Parse::Win32Registry;

use strict;
use warnings;

our $VERSION = '0.41';

use base qw(Exporter);

use Carp;
use Encode;
use Parse::Win32Registry::Base qw(:all);
use Parse::Win32Registry::Win95::File;
use Parse::Win32Registry::WinNT::File;

our @EXPORT_OK = qw(
    convert_filetime_to_epoch_time
    iso8601
    hexdump
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

*convert_filetime_to_epoch_time = \&Parse::Win32Registry::unpack_windows_time;

sub enable_warnings {
    $Parse::Win32Registry::Base::WARNINGS = 1;
}

sub disable_warnings {
    $Parse::Win32Registry::Base::WARNINGS = 0;
}

sub new {
    my $class = shift;
    my $filename = shift or croak "No filename specified";

    open my $regfile, "<", $filename or croak "Unable to open '$filename': $!";
    sysread($regfile, my $sig, 4);
    if (!defined($sig) || length($sig) != 4) {
        log_error("Could not read registry file header");
        return;
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
        log_error("Invalid registry file header");
        return;
    }
}

1;

__END__

=head1 NAME

Parse::Win32Registry - Parse Windows Registry Files

=head1 SYNOPSIS

    use strict;
    use Parse::Win32Registry qw( :REG_
                                 unpack_windows_time
                                 unpack_unicode_string );

    my $filename = shift or die "Filename?";

    my $registry = Parse::Win32Registry->new($filename)
        or die "'$filename' is not a registry file\n";
    my $root_key = $registry->get_root_key
        or die "Could not get root key of '$filename'\n";

    # Code robustly by assuming that get_subkey or get_value
    # might return nothing

    # The following code works on USER.DAT or NTUSER.DAT files

    my $software_key = $root_key->get_subkey(".DEFAULT\\Software")
                    || $root_key->get_subkey("Software");

    if (defined($software_key)) {
        my @user_key_names = (
          "Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
          "Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU",
        );

        foreach my $name (@user_key_names) {
            if (my $key = $software_key->get_subkey($name)) {
                print "\n", $key->as_string, "\n";
                foreach my $value ($key->get_list_of_values) {
                    print $value->as_string, "\n";
                }
            }
        }

        # This demonstrates how you can deal with a binary value
        # that contains a Unicode string
        foreach my $ver (qw(8.0 9.0 10.0 11.0)) {
            my $key_name = "Microsoft\\Office\\$ver\\Common\\UserInfo";
            if (my $key = $software_key->get_subkey($key_name)) {
                print "\n", $key->as_string, "\n";
                my @value_names = qw(UserName UserInitials Company);
                foreach my $value_name (@value_names) {
                    if (my $value = $key->get_value($value_name)) {
                        print $value->as_string, "\n";
                        my $data = $value->get_data;
                        my $string = unpack_unicode_string($data);
                        print "$value_name = '$string'\n";
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
        );

        foreach my $name (@software_key_names) {
            if (my $key = $software_key->get_subkey($name)) {
                print "\n", $key->as_string, "\n";
                foreach my $value ($key->get_list_of_values) {
                    print $value->as_string, "\n";
                }
            }
        }

        # This demonstrates how you can deal with a Unix date
        # found in a registry value
        my $key_name = "Microsoft\\Windows NT\\CurrentVersion";
        if (my $curver_key = $software_key->get_subkey($key_name)) {
            print "\n", $curver_key->as_string, "\n";
            if (my $value = $curver_key->get_value("InstallDate")) {
                print $value->as_string, "\n";
                my $time = $value->get_data;
                print "InstallDate = ",
                    scalar gmtime $time, " GMT\n";
                print "InstallDate = ",
                    scalar localtime $time, " Local\n";
            }
        }
    }

    # The following code works on SYSTEM.DAT or SYSTEM files

    my $system_key = $root_key->get_subkey("System") || $root_key;

    my $ccs_name = "CurrentControlSet"; # default for Win95
    if (my $key = $system_key->get_subkey("Select")) {
        my $current_value = $key->get_value("Current");
        $ccs_name = sprintf("ControlSet%03d", $current_value->get_data);
        print "CurrentControlSet = $ccs_name\n";
    }

    my $ccs_key = $system_key->get_subkey($ccs_name);

    if (defined($ccs_key)) {
        my @system_key_names = (
            "Control\\ComputerName\\ComputerName",
            "Control\\TimeZoneInformation",
        );

        foreach my $name (@system_key_names) {
            if (my $key = $ccs_key->get_subkey($name)) {
                print "\n", $key->as_string, "\n";
                foreach my $value ($key->get_list_of_values) {
                    print $value->as_string, "\n";
                }
            }
        }

        # This demonstrates how you can deal with a Windows date
        # found in a registry value
        my $key_name = "Control\\Windows";
        if (my $windows_key = $ccs_key->get_subkey($key_name)) {
            print "\n", $windows_key->as_string, "\n";
            if (my $value = $windows_key->get_value("ShutdownTime")) {
                print $value->as_string, "\n";
                my $data = $value->get_data;
                my $time = unpack_windows_time($data);
                print "ShutdownTime = ",
                    scalar gmtime $time, " GMT\n";
                print "ShutdownTime = ",
                    scalar localtime $time, " Local\n";
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

It supports both
Windows NT registry files (Windows NT, 2000, XP, 2003, Vista)
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
This avoids any delay in parsing an entire registry file to obtain a
Key or Value object as it is expected that most code will only be
extracting a subset of the keys and values contained in a registry
file.

=head2 Registry Object Methods

=over 4

=item $registry = Parse::Win32Registry->new( 'filename' )

Creates a new Registry object for the specified registry file.

=item $registry->get_root_key

Returns the root Key object of the registry file.

The root key of a registry file is not the same as one of the virtual
roots of the registry (HKEY_LOCAL_MACHINE, HKEY_USERS, etc) that you
may be familiar with from using tools such as REGEDIT.

The names of root keys vary by operating system and by file.
For example, the name of the root key of a Windows XP NTUSER.DAT file
is '$$$PROTO.HIV' and the name of the root key of a Windows 98
USER.DAT file is the empty string ''.

=item $registry->get_virtual_root_key

=item $registry->get_virtual_root_key( 'virtual root key name' )

Returns the virtual root Key object of the registry file.

In all respects this is exactly the same as the root Key object,
except that it pretends to be a virtual root by simply faking its name.
It guesses the virtual root key name
by looking at the filename of the registry file.
For example, if the filename contains 'SYSTEM'
the virtual root key will be named 'HKEY_LOCAL_MACHINE\\SYSTEM'.
If the guess fails (because the filename is not recognised)
the virtual root key will be named 'HKEY_UNKNOWN'.

You can override the guess by supplying your own root key name.
You can use this to pass in your preferred root key name.
For example, you could pass the filename of the registry file in as
the virtual root key name, which would then cause the filename to
appear as part of each key's path.

=item $registry->get_timestamp

Returns the embedded timestamp for the registry file as a time value
(the number of seconds since your computer's epoch)
suitable for passing to gmtime or localtime.

Only Windows NT registry files have an embedded timestamp.

Returns nothing if the date is out of range
or if called on a Windows 95 registry file

=item $registry->get_timestamp_as_string

Returns the timestamp as a ISO 8601 string,
for example, '2010-05-30T13:57:11Z'.
The Z indicates that the time is GMT ('Zero Meridian').

Returns the string '(undefined)' if the date is out of range
or if called on a Windows 95 registry file.

=item $registry->get_embedded_filename

Returns the embedded filename for the registry file.

Only Windows NT registry files have an embedded filename.

Returns nothing if called on a Windows 95 registry file

=back

=head2 Key Object Methods

=over 4

=item $key->get_name

Returns the name of the key. The root key of a Windows 95 based
registry file does not have a name; this is returned as an empty
string.

=item $key->get_path

Returns the path to the key. This shows the all of the keys
from the root key to the current key, 
joined by the path separator '\\'.

=item $key->get_class_name

Returns a string containing the class name associated with a key.
Only a very few Windows NT registry key have class names.

Returns nothing if the key has no class name
or if called on a Windows 95 registry key.

=item $key->get_subkey( 'key name' )

Returns a Key object for the specified subkey name.
If a key with that name does not exist, nothing will be returned.

You can specify a path to a subkey by separating keys
using the path separator '\\'. For example:

    $key->get_subkey('Software\\Microsoft\\Windows')

A path is always relative to the current key.
It should start with the name of the first subkey in the path,
not the current key.
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

=item $key->as_regedit_export

Returns the path of the key as a string
in the Windows Registry Editor Version 5.00 export format.

If used in conjunction with the get_virtual_root_key method
of Registry objects this should generate key paths
interoperable with those exported by REGEDIT.

=item $key->print_summary

Prints $key->as_string to standard output.

=item $key->get_parent

Returns a Key object for parent of the current key.
If the key does not have a valid parent key
(which will normally only occur for the root key)
nothing will be returned.

=item $key->is_root

Returns true if this key is the root key.

=back

=head2 Value Object Methods

=over 4

=item $value->get_name

Returns the name of the value.
In both Windows NT and Windows 95 based registry files
you can get values without a name.
This is returned as an empty string.

=item $value->get_type

Returns the integer representing the type of the value
(where 1 is a REG_SZ, 2 is a REG_EXPAND_SZ, etc).
The constants for the value types can be imported from
the Parse::Win32Registry module with

    use Parse::Win32Registry qw( :REG_ );

=item $value->get_type_as_string

Returns the type of the value as a string instead of an integer constant,
making it more suitable for printed output.

=item $value->get_data

Returns the data for the value.

REG_SZ and REG_EXPAND_SZ values will be returned as strings.
String data will be converted from Unicode (UCS-2LE) for Windows
NT based registry files.
Any terminating null characters will be removed.

REG_MULTI_SZ values will be returned as a list of strings when called
in an array context, and as a string with each element separated by
the list separator $" when called in a scalar context.
The list separator defaults to the space character.
String data will be converted from Unicode (UCS-2LE) for Windows
NT based registry files.

    # get REG_MULTI_SZ data as a string
    my $data = $multi_sz_value->get_data;

    # get REG_MULTI_SZ data as a list
    my @data = $multi_sz_value->get_data;

REG_DWORD values are unpacked and returned as unsigned integers.

All other types are returned as packed binary strings.
To extract data from these packed binary strings,
you will need to use Perl's unpack function,
or one of the provided support functions.

Nothing will be returned if the data is invalid.

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

=item $value->get_raw_data

Returns the data for a value exactly as it was read from the registry,
without the processing normally performed by get_data.

It is intended for those rare occasions
when you need to access binary data that has been
inappropriately stored in 
a REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ, or REG_DWORD value.

=item $value->as_string

Returns the name, type, and data for the value as a string,
safe for printed output.

'(Default)' will be used for the names of
those values that do not have names.

=item $value->as_regedit_export

Returns the name, type, and data for the value as a string,
in the Windows Registry Editor Version 5.00 export format.

'@' will be used for the names of 
those values that do not have names.

This should generate values
interoperable with those exported by REGEDIT.

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

You can import individual types by specifying them, for example:

    use Parse::Win32Registry qw( REG_SZ REG_DWORD );

=head2 Support Functions

Parse::Win32Registry will export the following support functions
on request.

=over 4

=item unpack_windows_time( $filetime )

Returns the epoch time for the given Win32 FILETIME.
A Win32 FILETIME is a 64-bit integer
containing the number of 100-nanosecond intervals since January 1st, 1601
and can sometimes be found in Windows NT registry values.
It should be passed as 8 bytes of packed binary data.

undef will be returned if the date is earlier than your computer's epoch.
The epoch begins at January 1st, 1970 on Unix and Windows machines.

(To avoid changing any existing scripts,
this function can also be called by its previous name of
convert_filetime_to_epoch_time.)

=item iso8601( $epoch_time )

Returns the ISO8601 string for the given $epoch_time,
for example, '2010-05-30T13:57:11Z'.

The string '(undefined)' will be returned if the epoch time is out of range.

    use Parse::Win32Registry qw( unpack_windows_time iso8601 );

    ...
    
    my $data = $value->get_data;

    # extract the Win32 FILETIME found at the start of the data
    my $time = unpack_windows_time($data);
    my $time_as_string = iso8601($time);
    print "$time_as_string\n";

=item unpack_unicode_string( $data )

Extracts a Unicode (UCS-2LE) string from the given binary data.
Any terminating null characters are dropped. 
Unicode (UCS-2LE) strings are sometimes encountered
in Windows NT registry REG_BINARY values.

Note that REG_SZ, REG_EXPAND_SZ, and REG_MULTI_SZ values
do not need any special handling
as they are automatically decoded
by the get_data method of a Value object.

In a scalar context, it will return the first Unicode string found.
In an array context, it will return all of the Unicode strings
found in the data.

    use Parse::Win32Registry qw( unpack_unicode_string );

    ...
    
    my $data = $value->get_data;

    # extract the unicode string at the start of the data
    my $string = unpack_unicode_string($data);
    print "$string\n";

=item hexdump( $data )

Returns a string containing a hex dump
of the supplied data in rows of 16 bytes.

=back

=head1 HANDLING INVALID DATA

Since version 0.40 the Parse::Win32Registry library generates
warnings to indicate errors with the registry file being read
instead of throwing a fatal exception.

If the error is severe, a scalar method 
will return nothing and a list method
will return an empty list.
So calling get_subkey or get_value will return nothing
if there is severe error with the specified key or value
and calling get_list_of_subkeys or get_list_of_values will return
an empty list
if there are severe errors with all of the subkeys or values.
If there are severe errors with only some of the subkeys or values,
then a partial list will be returned.

However, some errors are survivable.
Windows 95 keys store the key information in two places.
If information is only retrieved from the first place,
the Key object will exist, but will have no name and no values.
Windows NT values generally store data in another area
of the registry file. 
If the data cannot be retrieved, the Value object will exist,
but will return nothing for its data.

If available, information about the key you were in when
you encountered an error will be appended to the error message.

Warning messages can be disabled using:

    Parse::Win32Registry::disable_warnings;

and re-enabled using:

    Parse::Win32Registry::enable_warnings;

You can prevent undefined Key or Value objects from causing
your scripts to die by checking they exist
before calling any methods on them:

    if (my $key = $root_key->get_subkey("Software\\Perl")) {
        print $key->as_string, "\n";
        if (my $value = $key->get_value("Version")) {
            print $value->as_string, "\n";
        }
    }

=head1 ADVANCED METHODS

These methods are intended for those
who want to look at the structure of a registry file,
but with something a little more helpful than a hex editor.

They are not designed for pulling data out of keys and values.
They are designed for providing technical information about keys and values.

Most of these methods are demonstrated by the supplied regscan.pl script.

=head2 Registry Object Methods

=over 4

=item $registry->get_next_entry

Iterates through the entries in a registry file,
returning them one by one,
beginning with the first.

Each entry represents
a single record in the RGKN block of a Windows 95 registry file,
or a single record in a HBIN block of a Windows NT registry file.

These entries will include unused and potentially invalid entries.

=item $registry->move_to_first_entry

Resets the iterator to the first entry in the registry file.

=back

=head2 Entry Object Methods

=over 4

=item $entry->get_offset

Returns the position of the entry relative to the start of the file.

=item $entry->as_string

Returns a string representation of the entry.

If the entry is a valid Key or Value object,
then as_string will delegate the response
to the as_string method of that object.

=item $entry->parse_info

Returns a string containing a summary of the parser information
for that entry.

If the entry is a valid Key or Value object,
then parse_info will delegate the response
to the parse_info method of that object.

=item $entry->as_hexdump

Returns a string containing a hex dump
of the on-disk data for the entry.

=back

=head2 Key Object Methods

=over 4

=item $key->parse_info

Returns a string containing a summary of the parser information
for the key.

=item $key->as_hexdump

Returns a string containing a hex dump
of the on-disk data for the key.

=back

=head2 Value Object Methods

=over 4

=item $value->parse_info

Returns a string containing a summary of the parser information
for the value.

=item $value->as_hexdump

Returns a string containing a hex dump
of the on-disk data for the value.

=back

=head1 SCRIPTS

All of the supplied scripts are intended to be used either as tools
or as examples for you to modify and develop.

When specifying subkeys on the command line, note that you need to
quote the backslashes on Unix systems, so:

    regdump.pl ntuser.dat "software\microsoft\windows nt"

should be entered as:

    regdump.pl ntuser.dat "software\\microsoft\\windows nt"

or:

    regdump.pl ntuser.dat 'software\microsoft\windows nt'

=head2 regdump.pl

regdump.pl is used to display the keys and values of a registry file.

Type regdump.pl on its own to see the help:

    regdump.pl <filename> [subkey] [-r] [-v] [-x]
        -r or --recurse     traverse all child keys from the root key
                            or the subkey specified
        -v or --values      display values
        -x or --hexdump     display value data as a hex dump

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
    ...

Remember to quote any subkey path that contains spaces:

    regdump.pl ntuser.dat "software\microsoft\windows nt"

=head2 regexport.pl

regexport.pl will display registry keys and values
in the Windows Registry Editor Version 5.00 format
used by REGEDIT on Windows 2000 and later.

Type regexport.pl on its own to see the help:

    regexport.pl <filename> [subkey] [-r]
        -r or --recurse     traverse all child keys from the root key
                            or the subkey specified

It usage is very similar to regdump.pl,
except that values are always displayed.

Subkeys are displayed as comments when not recursing.

=head2 regclassnames.pl

regclassnames.pl will display registry keys that have class names.
Only a very few Windows NT registry key have class names.

Type regclassnames.pl on its own to see the help:

    regclassnames.pl <filename> [subkey]

=head2 regdiff.pl

regdiff.pl is used to compare two registry files and identify the
differences between them.

Type regdiff.pl on its own to see the help:

    regdiff.pl <filename1> <filename2> [subkey] [-p] [-v]
        -p or --previous    show the previous key or value
                            (this is not normally shown)
        -v or --values      display values

When comparing Windows NT based registry files, regdiff.pl can
identify if a key has been updated by comparing timestamps.
When comparing Windows 95 based registry files, it needs to check all
its values to see if any have changed.

You can limit the comparison by specifying an initial subkey.

=head2 regfind.pl

regfind.pl is used to search the keys, values, data, or types
of a registry file for a matching string.

Type regfind.pl on its own to see the help:

    regfind.pl <filename> <search-string> [-k] [-v] [-d] [-t]
        -k or --key         search key names for a match
        -v or --value       search value names for a match
        -d or --data        search value data for a match
        -t or --type        search value types for a match

To search for the string "recent" in the names of any keys or values:

    regfind.pl ntuser.dat recent -kv

To search for the string "administrator" in the data of any values:

    regfind.pl ntuser.dat administrator -d

To search for the string "username" in the name of any values:

    regfind.pl ntuser.dat username -v

To search for urls in the data of any values:

    regfind.pl software "http://" -d

To search for key names that look like file extensions:

    regfind.pl software "^\.[a-z0-9]+" -k

To list all REG_MULTI_SZ values:

    regfind.pl ntuser.dat -t multi_sz

Search strings are not case-sensitive.

=head2 regscan.pl

regscan.pl dumps all the entries in a registry file.
This will include defunct keys and values that are no longer part
of the current active registry.

Type regscan.pl on its own to see the help:

    regscan.pl <filename> [-d] [-s] [-x]
        -d or --debug       show the technical information for an entry
                            instead of the string representation
        -s or --silent      suppress the display of warning messages
                            for invalid keys and values
        -x or --hexdump     show the on-disk entries as a hex dump

=head2 regstats.pl

regstats.pl counts the number of keys and values in a registry file.
It will also provide a count of each value type if requested.

Type regstats.pl on its own to see the help:

    regstats.pl <filename> [-t]
        -t or --types       count value types

=head2 regtimeline.pl

regtimeline.pl displays keys and values in date order.

As only Windows NT based registry keys provide timestamps,
this script only works on Windows NT registry files.

You can limit the display to a given number of days
(counting back from the timestamp of the last key).

Type regtimeline.pl on its own to see the help:

    regtimeline.pl <filename> [subkey] [-l <number>] [-v]
        -l or --last        display only the last <number> days
                            of registry activity
        -v or --values      display values

=head2 regtree.pl

regtree.pl simply displays the registry as an indented tree,
optionally displaying the values of each key.

Type regtree.pl on its own to see the help:

    regtree.pl <filename> [subkey] [-v]
        -v or --values      display values

=head2 regview.pl

regview.pl is a GTK+ Registry Viewer.
It offers the traditional tree of registry keys on the left hand side,
a list of values on the right,
and a hex dump of the value data at the bottom.

It requires Gtk2-Perl to be installed. 
Links to Windows binaries can be found via the project home page at
L<http://gtk2-perl.sourceforge.net/win32/>.

=head1 ACKNOWLEDGEMENTS

This would not have been possible without the work of those people who have
analysed and documented the structure of Windows Registry files, namely:
the WINE Project (see misc/registry.c in older releases),
the Samba Project (see utils/editreg.c and utils/profiles.c),
B.D. (for WinReg.txt),
and Petter Nordahl-Hagen (see chntpw's ntreg.h).

My appreciation to those who have sent me their thanks.

=head1 AUTHOR

James Macfarlane, E<lt>jmacfarla@cpan.orgE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006,2007,2008 by James Macfarlane

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

THIS PACKAGE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION,
THE IMPLIED WARRANTIES OF MERCHANTIBILITY AND FITNESS
FOR A PARTICULAR PURPOSE.

=cut
