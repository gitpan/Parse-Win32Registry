package Parse::Win32Registry;

use strict;
use warnings;

our $VERSION = '0.50';

use base qw(Exporter);

use Carp;
use Encode;
use Parse::Win32Registry::Base qw(:all);
use Parse::Win32Registry::Win95::File;
use Parse::Win32Registry::WinNT::File;

our @EXPORT_OK = (
    # include old function names for backwards compatibility
    'convert_filetime_to_epoch_time',
    'formatted_octets',
    @Parse::Win32Registry::Base::EXPORT_OK
);

our %EXPORT_TAGS = (
    REG_      => [grep { /^REG_[A-Z_]*$/ } @EXPORT_OK],
    all       => [@EXPORT_OK],
    functions => [grep { /^[a-z0-9_]*$/ } @EXPORT_OK],
    constants => [grep { /^[A-Z_]*$/ } @EXPORT_OK],
);

*convert_filetime_to_epoch_time = \&Parse::Win32Registry::unpack_windows_time;
*formatted_octets = \&Parse::Win32Registry::format_octets;

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
        warnf("Could not read registry file header");
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
        warnf("Invalid registry file header");
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
Key or Value object as most code only looks at a subset of the keys
and values contained in a registry file.

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
USER.DAT file is an empty string.

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
or if called on a Windows 95 registry file.

=item $registry->get_timestamp_as_string

Returns the timestamp as a ISO 8601 string,
for example, '2010-05-30T13:57:11Z'.
The Z indicates that the time is GMT ('Zero Meridian').

Returns the string '(undefined)' if the date is out of range
or if called on a Windows 95 registry file.

=item $registry->get_embedded_filename

Returns the embedded filename for the registry file.

Only Windows NT registry files have an embedded filename.

Returns nothing if called on a Windows 95 registry file.

=item $registry->get_filename

Returns the filename of the registry file.

=item $registry->get_length

Returns the length of the registry file.

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
joined by the path separator '\'.

=item $key->get_subkey( 'key name' )

Returns a Key object for the specified subkey name.
If a key with that name does not exist, nothing will be returned.

You can specify a path to a subkey by separating keys
using the path separator '\'. Remember
to quote any '\' characters with a preceding '\'.
For example:

    $key->get_subkey('Software\\Microsoft\\Windows')

A path is always relative to the current key.
It should start with the name of the first subkey in the path,
not the current key.
If any key in the path does not exist, nothing will be returned.

=item $key->get_value( 'value name' )

Returns a Value object for the specified value name.
If a value with that name does not exist, nothing will be returned.

The default value (displayed as '(Default)' by REGEDIT)
does not actually have a name. It can obtained by supplying
an empty string, e.g. $key->get_value('');

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

Returns the timestamp as an ISO 8601 string,
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
The string will be terminated with a newline character.

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

=item $key->get_class_name

Returns a string containing the class name associated with a key.
Only a very few Windows NT registry key have class names.

Returns nothing if the key has no class name
or if called on a Windows 95 registry key.

=item $key->get_security

Returns a Security object containing the security information
for the key. Only Windows NT registry keys have security information.

Returns nothing if called on a Windows 95 registry key.

=item $key->get_subkey_iterator

Returns an iterator for retrieving the subkeys of the current key.
Each time the get_next method of the iterator is used,
it will return a single Key object.
Keys will be returned one by one
until the end of the list is reached,
when nothing will be returned.

It can be used as follows:

    my $subkey_iter = $key->get_subkey_iterator;
    while (my $subkey = $subkey_iter->get_next) {
        # do something with $subkey
        ...
    }

Note that it is usually simpler to just use $key->get_list_of_subkeys.
An iterator may be useful when you need to
control the amount of processing you are performing,
such as programs that need to remain responsive to user actions.

=item $key->get_value_iterator

Returns an iterator for retrieving the values of the current key.
Each time the get_next method of the iterator is used,
it will return a single Value object.
Values will be returned one by one
until the end of the list is reached,
when nothing will be returned.

It can be used as follows:

    my $value_iter = $key->get_value_iterator;
    while (my $value = $value_iter->get_next) {
        # do something with $value
        ...
    }

Note that it is usually simpler to just use $key->get_list_of_values.

=item $key->get_subtree_iterator

Returns an iterator for retrieving the entire subtree
of keys and values beginning at the current key.
Each time the get_next method of the iterator is used,
it will return either a Key object
or a Key object and a Value object.
Each value accompanies the key that it belongs to.
Keys or Key/Value pairs will be returned one by one
until the end of the list is reached,
when nothing will be returned.

It can be used as follows:

    my $subtree_iter = $key->get_subtree_iterator;
    while (my ($key, $value) = $subtree_iter->get_next) {
        if (defined $value) {
            # do something with $key and $value
            ...
        }
        else {
            # do something with $key
            ...
        }
    }

Keys and values will be returned in the following order:

    root_key
    root_key\key1
    root_key\key1, value1
    root_key\key1, value2
    root_key\key1\key2
    root_key\key1\key2, value3
    root_key\key1\key2, value4

If the iterator is used in a scalar context,
only Key objects will returned.

    my $subtree_iter = $key->get_subtree_iterator;
    while (my $key = $subtree_iter->get_next) {
        # do something with $key
        ...
    }

Keys will be returned in the following order:

    root_key
    root_key\key1
    root_key\key1\key2


Note that it may be simpler to write a recursive function
to process the keys and values.

    sub traverse {
        my $key = shift;

        # do something with $key
        ...

        foreach my $value ($key->get_list_of_values) {
            # do something with $value
            ...
        }

        foreach my $subkey ($key->get_list_of_subkeys) {
            # recursively process $key
            traverse($subkey);
        }
    }

    traverse($root_key);

=item $key->walk( \&callback );

Performs a recursive descent of all the keys
in the subtree starting with the calling key,
and calls the callback function for each key reached.

The callback function will be passed the current key.

    $key->walk( sub {
        my $key = shift;
        print $key->as_string, "\n";
    } );

    $key->walk( sub {
        my $key = shift;
        print $key->as_regedit_export;
        foreach my $value ($key->get_list_of_values) {
            print $value->as_regedit_export;
        }
    } );

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

REG_MULTI_SZ values will be returned as a list of strings when
called in a list context,
and as a string with each element separated by
the list separator $" when called in a scalar context.
(The list separator defaults to the space character.)
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

Returns the data for a value, making binary data safe for printed output.

REG_SZ and REG_EXPAND_SZ values will be returned directly from get_data,
REG_MULTI_SZ values will have their component strings prefixed by
indices to more clearly show the number of elements, and
REG_DWORD values will be returned as a hexadecimal number followed
by its parenthesized decimal equivalent.
All other types of values will be returned as a string of hex octets.

'(invalid data)' will be returned if the data is invalid
(i.e. when get_data returns undef).

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
The string will contain line breaks to ensure that
no line is longer than 80 characters.
Each line will be terminated with a newline character.

'@' will be used for the names of
those values that do not have names.

This should generate values
interoperable with those exported by REGEDIT.

=item $value->print_summary

Prints $value->as_string to standard output.

=back

=head2 Security Object Methods

Only Windows NT registry files contain security information
to control access to the registry keys.
This information is stored in security entries which are distributed
through the registry file separately from the keys that they apply to.
This allows the registry to share security information
amongst a large number of keys whilst unnecessary duplication.

Security entries link to other security entries in a circular chain,
each entry linking to the one that precedes it and the one that follows it.

=over 4

=item $security->get_security_descriptor

Returns a Security Descriptor Object representing the security descriptor
contained in the security information registry entry.

=item $security->get_next

Returns the next security object.

=item $security->get_previous

Returns the previous security object.

=item $security->get_reference_count

Returns the reference count for the security object.

=back

=head2 Security Descriptor Object Methods

A Security Descriptor object represents a security descriptor which
contains an owner SID, a primary group SID,
a System ACL, and a Discretionary ACL.

=over 4

=item $security_descriptor->get_owner

Returns a SID Object containing the Owner SID.

=item $security_descriptor->get_group

Returns a SID Object containing the primary group SID.

=item $security_descriptor->get_sacl

Returns an ACL Object containing the System ACL.
The System ACL contains those ACEs used for auditing.
Nothing will be returned if the security descriptor does not contain
a System ACL.

=item $security_descriptor->get_dacl

Returns an ACL Object containing the Discretionary ACL.
The Discretionary ACL contains those ACEs used for access control.
Nothing will be returned if the security descriptor does not contain
a Discretionary ACL.

=item $security_descriptor->as_stanza

Returns a multi-line string containing
the security descriptor formatted for presentation.
It will contain a line for the owner SID,
the group SID,
and each component ACE of the System ACL and the Discretionary ACL.
Each line will be terminated by a newline character.

=back

=head2 ACL Object Methods

An ACL object represents an Access Control List,
which comprises a list of Access Control Entries.

=over 4

=item $acl->get_list_of_aces

Returns a list of ACE Objects representing the ACEs
in the order they appear in the ACL.
If the ACL contains no ACEs, nothing will be returned.

=item $acl->as_stanza

Returns a multi-line string containing
the ACL formatted for presentation.
It will contain a line for each component ACE of the ACL.
Each line will be terminated by a newline character.

=back

=head2 ACE Object Methods

An ACE object represents an Access Control Entry.
An ACE describes the permissions assigned (the access mask)
to a Security Identifier (the trustee).

=over 4

=item $ace->get_type

Returns an integer containing the ACE type,
where 0 indicates an ACCESS_ALLOWED ACE,
1 an ACCESS_DENIED ACE, and
2 a SYSTEM_AUDIT ACE.
Typically you will encounter
ACCESS_ALLOWED and ACCESS_DENIED ACEs in Discretionary ACLs
and SYSTEM_AUDIT ACEs in System ACLs.

=item $ace->get_type_as_string

Returns the type as a string, rather than integer.

=item $ace->get_flags

Returns an integer containing the ACE flags.

=item $ace->get_access_mask

Returns an integer containing the ACE access mask.
The access mask controls what actions the trustee may perform with
the object the ACE applies to.

=item $ace->get_trustee

Returns a SID Object containing the trustee that this ACE
is associated with.

=item $ace->as_string

Returns a string containing
the ACE formatted for presentation.

=back

=head2 SID Object Methods

A SID object represents a Security Identifier.

=over 4

=item $sid->as_string

Returns a string containing the SID formatted for presentation.

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

=head1 SUPPORT FUNCTIONS

Parse::Win32Registry provides a number of support functions,
which are exported on request. All of the support functions can
be imported with:

    use Parse::Win32Registry qw( :functions );

=head2 Unpacking Binary Data

There are a number of functions for assisting in unpacking binary data
found in registry values.
These functions are exported on request:

    use Parse::Win32Registry qw( unpack_windows_time
                                 unpack_unicode_string
                                 unpack_sid
                                 unpack_ace
                                 unpack_acl
                                 unpack_security_descriptor );

These unpack functions also return the length
of the packed object when called in a list context.

For example, to extract one SID:

    my $sid = unpack_sid($data);

To extract a series of SIDs:

    my $pos = 0;
    while ($pos < length($data)) {
        my ($sid, $packed_len) = unpack_sid(substr($data, $pos));
        last if !defined $sid; # abort if SID not defined

        # ...do something with $sid...

        $pos += $packed_len; # move past the packed SID
    }

=over 4

=item $time = unpack_windows_time( $data )
=item ( $time, $packed_len ) = unpack_windows_time( $data )

Returns the epoch time for the Win32 FILETIME
contained in the supplied binary data.
A Win32 FILETIME is a 64-bit integer
containing the number of 100-nanosecond intervals since January 1st, 1601
and can sometimes be found in Windows NT registry values.

Returns nothing if the date is earlier than your computer's epoch.
The epoch begins at January 1st, 1970 on Unix and Windows machines.

When called in a list context, it will also return the space used
in the supplied data by the windows time.

(This function can also be called by its previous name of
convert_filetime_to_epoch_time.)

=item $str = unpack_unicode_string( $data )
=item ( $str, $packed_len ) = unpack_unicode_string( $data )

Extracts a Unicode (UCS-2LE) string from the supplied binary data.
Any terminating null characters are dropped.
Unicode (UCS-2LE) strings are sometimes encountered
in Windows NT registry REG_BINARY values.

Note that Unicode strings contained in
REG_SZ, REG_EXPAND_SZ, and REG_MULTI_SZ values
are already automatically decoded
by the get_data method of a Value object.

When called in a list context, it will also return the space used
in the supplied data by the Unicode string.

=item $sid = unpack_sid( $data )
=item ( $sid, $packed_len) = unpack_sid( $data )

Returns a SID Object representing the SID contained in the supplied data.
Returns nothing if the supplied data does not appear to contain a valid SID.

When called in a list context, it will also return the space used
in the supplied data by the SID.

=item $ace = unpack_ace( $data )
=item ( $ace, $packed_len ) = unpack_ace( $data )

Returns an ACE Object representing the ACE contained in the supplied data.
Returns nothing if the supplied data does not appear to contain a valid ACE.

When called in a list context, it will also return the space used
in the supplied data by the ACE.

=item $acl = unpack_acl( $data )
=item ( $acl, $packed_len ) = unpack_acl( $data )

Returns an ACL Object representing the ACL contained in the supplied data.
Returns nothing if the supplied data does not appear to contain a valid ACL.

When called in a list context, it will also return the space used
in the supplied data by the ACL.

=item $sd = unpack_security_descriptor( $data )
=item ( $sd, $packed_len ) = unpack_security_descriptor( $data )

Returns a Security Descriptor Object representing
the security descriptor contained in the supplied data.
Returns nothing if the supplied data does not appear to contain
a valid security descriptor.

When called in a list context, it will also return the space used
in the supplied data by the security descriptor.

=back

=head2 Formatting Data

These functions are exported on request:

    use Parse::Win32Registry qw( iso8601 hexdump );

=over 4

=item $str = iso8601( $epoch_time )

Returns the ISO8601 string for the supplied $epoch_time,
for example, '2010-05-30T13:57:11Z'.

The string '(undefined)' will be returned if the epoch time is out of range.

    my $data = $reg_binary_value->get_data;

    # extract the Win32 FILETIME starting at the 9th byte of $data
    my $time = unpack_windows_time( substr( $data, 8 ) );
    my $time_as_string = iso8601( $time );
    print "$time_as_string\n";

There are a number of ways of displaying a timestamp. For example:

    use Parse::Win32Registry qw(iso8601);
    use POSIX qw(strftime);
    print iso8601($key->get_timestamp);
    print scalar(gmtime($key->get_timestamp)), " GMT\n";
    print scalar(localtime($key->get_timestamp)), " Local\n";
    print strftime("%Y-%m-%d %H:%M:%S GMT",
                   gmtime($key->get_timestamp)), "\n";
    print strftime("%Y-%m-%d %H:%M:%S Local",
                   localtime($key->get_timestamp)), "\n";

Which might produce the following output:

    2000-08-06T23:42:36Z
    Sun Aug  6 23:42:36 2000 GMT
    Mon Aug  7 07:42:36 2000 Local
    2000-08-06 23:42:36 GMT
    2000-08-07 07:42:36 Local

=item $str = hexdump( $data )

Returns a multi-line string containing
a hexadecimal dump of the supplied data.
Each line will display 16 bytes in hexadecimal and ASCII,
and will be terminated by a newline character.

=back

=head2 Processing Multiple Registry Files Simultaneously

There are three support functions
that create iterators for simultaneously
processing the keys and values
of multiple registry files.
These functions are exported on request:

    use Parse::Win32Registry qw( make_multiple_subkey_iterator
                                 make_multiple_value_iterator
                                 make_multiple_subtree_iterator );


Handling lists of subkeys or values
should be done with a little care
as some of the processed registry files
may not contain the subkey or value being examined
and the list will contain missing entries:

    ($key1, $key2, undef, $key4)

One way of handling this is to use map to check that a key is defined
and return undef if the subkey or value is not present.

    @subkeys = map { defined $_ && $_->get_subkey('subkey') || undef } @keys;

    @values = map { defined $_ && $_->get_value('value') || undef } @keys;

=over 4

=item $iter = make_multiple_subkey_iterator( $key1, $key2, $key3, ... )

Returns an iterator for retrieving
the subkeys of the supplied Key objects.
Each call to the get_next method of the iterator
returns a reference to
a list of Key objects with the same name and path.
If any of the supplied Key objects
does not have a subkey with that name,
then that subkey will be undefined.

    my $subkey_iter = make_multiple_subkey_iterator($key1, $key2, ...);
    while (my ($subkey1, $subkey2, ...) = $subkey_iter->get_next) {
        ...
    }

    my $subkey_iter = make_multiple_subkey_iterator($key1, $key2, ...);
    while (my @subkeys = $subkey_iter->get_next) {
        foreach my $subkey (@subkeys) {
            if (defined $subkey) {
                ...
            }
        }
    }

=item $iter = make_multiple_value_iterator( $key1, $key2, $key3, ... )

Returns an iterator for retrieving
the values of the supplied Key objects.
Each call to the get_next method of the iterator
returns a reference to
a list of Value objects with the same name.
If any of the supplied Key objects
does not have a value with that name,
then that value will be undefined.

    my $value_iter = make_multiple_value_iterator($key1, $key2, ...);
    while (my ($value1, $value2, ...) = $value_iter->get_next) {
        ...
    }

=item $iter = make_multiple_subtree_iterator( $key1, $key2, $key3, ... )

Returns an iterator for retrieving
the immediate subkeys and all descendant subkeys of the supplied Key objects.
Each call to the get_next method of the iterator
returns a list of Key objects with the same name and path.
If any of the supplied Key objects
does not have a subkey with that name,
then that subkey will be undefined.

Each call to the get_next method of the iterator
returns it will return
either a reference to a list of Key objects
or a reference to a list of Key objects
and a reference to a list of a Value objects,
with each list of values accompanying the list of keys that they belong to.
Nothing is returned when the end of the list is reached.

    my $subtree_iter = make_multiple_subtree_iterator($key1, $key2, ...);
    while (my $subkeys_ref = $tree_iter->get_next) {
        # do something with @$subkeys_ref
    }

    my $subtree_iter = make_multiple_subtree_iterator($key1, $key2, ...);
    while (my ($subkeys_ref, $values_ref) = $tree_iter->get_next) {
        if (defined $values_ref) {
            # do something with @$subkeys_ref and @$values_ref
            for (my $i = 0; $i < @$values_ref; $i++) {
                print $values_ref->[$i]->as_string, "\n";
            }
            ...
        }
        else {
            # do something with @$subkeys_ref
            my $first_defined_subkey = (grep { defined } @$subkeys_ref)[0];
            print $first_defined_subkey->as_string, "\n";
            ...
        }
    }

=back

=head2 Comparing Keys and Values

These functions are exported on request:

    use Parse::Win32Registry qw( compare_multiple_keys
                                 compare_multiple_values );

=over 4

=item @changes = compare_multiple_keys( $key1, $key2, ... );

Returns a list of strings
describing the differences found between the supplied keys.
The keys are compared in the order they are supplied.
If one of the supplied keys is undefined,
it is assumed to have been deleted.

The possible changes are 'ADDED', and 'DELETED',
and for Windows NT registry keys (which have timestamps)
'NEWER', and 'OLDER'.

For example, compare_multiple_keys($k1, $k2, $k3)
would return the list ('', 'NEWER', '')
if $k2 had a more recent timestamp than $k1,
but $k3 had the same timestamp as $k2.

You can count the number of changed keys using the grep operator:

    my $num_changes = grep { $_ } @changes;

=item @changes = compare_multiple_values( $value1, $value2, ... );

Returns a list of strings
describing the differences found between the supplied values.
The values are compared in the order they are supplied.
If one of the supplied values is undefined,
it is assumed to have been deleted.

The possible changes are 'ADDED', 'DELETED', and 'CHANGED'.

For example, compare_multiple_keys($v1, $v2, $v3)
would return the list ('', 'ADDED', 'CHANGED')
if $v2 exists but $v1 did not,
and $v3 had different data from $v2.

You can count the number of changed values using the grep operator:

    my $num_changes = grep { $_ } @changes;

=back

=head1 HANDLING INVALID DATA

Since version 0.50 the Parse::Win32Registry library
can display warnings to indicate errors with the registry file being read.
This has to be switched on using:

    Parse::Win32Registry->enable_warnings;

It can be switched off again with:

    Parse::Win32Registry->disable_warnings;

If the parser is unable to successfully parse the current registry entry,
nothing will be returned.
$key->get_subkey or $key->get_value
will return an undefined value (and display a warning).
$key->get_list_of_subkeys or $key->get_list_of_values
will return an empty list (and display warnings)
if all of the subkeys or values cannot be parsed.
If only some of the subkeys or values cannot be parsed,
then a partial list will be returned
(and warnings displayed only for those subkeys or values
that could not be parsed).

However, some errors are survivable,
and allow the creation of keys and values with incomplete information.
Specifically,
Windows 95 keys store their information in two different sections
of the registry file.
If information is only retrieved from the first section,
a Key object will be created,
but it will have no name and no values.
$key->get_name will return an empty string and
$key->get_list_of_values will return an empty list.
Windows NT values generally store their data
in a separate area from the value information.
If the value can be parsed, but the data cannot,
a Value object will be created,
but it will have no data.
$value->get_data will return nothing.

The most robust way of handling keys or values or data
is to check that they are defined before processing them.
For example:

    my $key = $root_key->get_subkey( "Software\\Perl" );
    if ( defined $key ) {
        print $key->as_string, "\n";
        my $value = $key->get_value( "Version" );
        if ( defined $value ) {
            print $value->as_string, "\n";
            my $data = $value->get_data;
            if ( defined $data ) {
                # process $data in some way...
            }
        }
    }

You may not feel this robustness is required for smaller scripts.

=head1 LOWER LEVEL METHODS FOR PROCESSING REGISTRY FILES

These methods are intended for those
who want to look at the structure of a registry file,
but with something a little more helpful than a hex editor.

They are not designed for pulling data out of keys and values.
They are designed for providing technical information about keys and values.

Most of these methods are demonstrated by the supplied regscan.pl script.

=head2 Registry Object Methods

=over 4

=item $registry->get_entry_iterator

Returns an iterator for retrieving all the entries in a registry file.
Each time the get_next method of the iterator is used,
it will return a single Entry object.
Entries will be returned one by one
until the end of the registry file is reached,
when nothing will be returned.

    my $entry_iter = $registry->get_entry_iterator;
    while (my $entry = $entry_iter->get_next) {
        ...
    }

This replaces the following approach introduced in 0.40:

    $registry->move_to_first_entry;
    while (my $entry = $registry->get_next_entry) {
        ...
    }

=item $registry->get_hbin_iterator

Returns an iterator for retrieving all the hbins in a registry file.
Windows NT registry files are composed of hbins,
with each hbin actually containing the entries.
Each time the get_next method of the iterator is used,
it will return a single Hbin object.
Hbins will be returned one by one
until the end of the registry file is reached,
when nothing will be returned.

This method returns nothing for Windows 95 registry files.

So for Windows NT registry files,
instead of using $registry->get_entry_iterator
entries can also be processed one hbin at a time:

    my $hbin_iter = $registry->get_hbin_iterator;
    while (my $hbin = $hbin_iter->get_next) {
        my $entry_iter = $hbin->get_entry_iterator;
        while (my $entry = $entry_iter->get_next) {
            ...
        }
    }

=back

=head2 Hbin Object Methods

=over 4

=item $hbin->get_entry_iterator

Returns an iterator for retrieving all the entries in an hbin.
Each time the get_next method of the iterator is used,
it will return a single Entry object.
Entries will be returned one by one
until the end of the hbin is reached,
when nothing will be returned.

    my $entry_iter = $hbin->get_entry_iterator;
    while (my $entry = $entry_iter->get_next) {
        ...
    }

=item $hbin->get_offset

Returns the position of the hbin relative to the start of the file.

=item $hbin->get_length

Returns the length of the hbin.

=item $hbin->parse_info

Returns a string containing a summary of the parser information
for the hbin.

=item $entry->unparsed

Returns a string containing a hex dump
of the unparsed on-disk data for the hbin header.

=item $entry->get_raw_bytes

Returns the unparsed on-disk data for the hbin header.

=back

=head2 Entry Object Methods

=over 4

=item $entry->get_offset

Returns the position of the entry relative to the start of the file.

=item $entry->get_length

Returns the length of the entry.

Entries in Windows NT registry files vary in size;
entries in Windows 95 registry files are always 28 bytes in size
(as only the RGKN block is examined).

=item $entry->get_tag

Returns a string containing a descriptive tag for the entry.

For Windows NT registry entries, the tags reflect the
signatures used to identify them.
These are:
'nk' for keys;
'vk' for values;
'sk' for security entries;
and 'lf', 'lh', 'li', or 'ri' for subkey lists.
Entries that do not have signatures will return ''.
Unidentified entries include
value lists, value data, and the class names of keys.

For Windows 95 registry files, the tag
reflects the part of the registry file the entry is from
and is always set to 'rgkn'.

=item $entry->is_allocated

Returns a boolean value indicating the 'allocated' state of a
Windows NT registry entry.

This value has no meaning for Windows 95 registry entries,
and is always set to 0.

=item $entry->as_string

Returns a string representation of the entry.

If the entry is a valid Key, Value, or Security object,
then as_string will call the as_string method of that object.

=item $entry->parse_info

Returns a string containing a summary of the parser information
for that entry.

If the entry is a valid Key, Value, or Security object,
then parse_info will call the parse_info method of that object.

=item $entry->unparsed

Returns a string containing a hex dump
of the unparsed on-disk data for the entry.

=item $entry->get_raw_bytes

Returns the unparsed on-disk data for the entry.

=item $entry->looks_like_key

Returns a boolean indicating whether this entry
can be successfully parsed as a Key object.
If it returns true, then
the entry will support all the methods provided by Key objects
(e.g. get_timestamp, get_list_of_subkeys, get_list_of_values, etc.)

=item $entry->looks_like_value

Returns a boolean indicating whether this entry
can be successfully parsed as a Value object.
If it returns true, then
the entry will support all the methods provided by Value objects
(e.g. get_type, get_data, etc.)

=item $entry->looks_like_security

Returns a boolean indicating whether this entry
can be successfully parsed as a Security object.
If it returns true, then
the entry will support all the methods provided by Security objects
(e.g. get_security_descriptor, etc.)

=back

=head1 SCRIPTS

All of the supplied scripts are intended to be used either as tools
or as examples for you to modify and develop.

Try regdump.pl or regshell.pl to look at a registry file
from the command line, or regview.pl if you want a GUI.
If you want to compare registry files,
try regmultidiff.pl from the command line
or regcompare.pl if you want a GUI.
Edit the scripts to customize them for your own requirements.

If you specify subkeys on the command line, note that you need to
quote the subkey on Windows if it contains spaces:

    regdump.pl ntuser.dat "software\microsoft\windows nt"

You will also need to quote backslashes and spaces in Unix shells:

    regdump.pl ntuser.dat software\\microsoft\\windows\ nt

unless you use single quotes:

    regdump.pl ntuser.dat 'software\microsoft\windows nt'

=head2 regclassnames.pl

regclassnames.pl will display registry keys that have class names.
Only a very few Windows NT registry key have class names.

Type regclassnames.pl on its own to see the help:

    regclassnames.pl <filename> [subkey]

=head2 regcompare.pl

regview.pl is a GTK+ program for comparing multiple registry files.
It displays a tree of the registry keys and values
highlighting the changed keys and values,
and a table detailing the actual changes.

It requires Gtk2-Perl to be installed.
Links to Windows binaries can be found via the project home page at
L<http://gtk2-perl.sourceforge.net/win32/>.

Filenames of registry files to compare can be supplied on the command line:

    regcompare.pl <filename1> <filename2> <filename3> ...

=head2 regdump.pl

regdump.pl is used to display the keys and values of a registry file.

Type regdump.pl on its own to see the help:

    regdump.pl <filename> [subkey] [-r] [-v] [-x] [-c] [-s] [-o]
        -r or --recurse     traverse all child keys from the root key
                            or the subkey specified
        -v or --values      display values
        -x or --hexdump     display value data as a hex dump
        -c or --class-name  display the class name for the key (if present)
        -s or --security    display the security information for the key,
                            including the owner and group SIDs,
                            and the system and discretionary ACLs (if present)
        -o or --owner       display only the owner SID for the key (if present)

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

=head2 regexport.pl

regexport.pl will display registry keys and values
in the Windows Registry Editor Version 5.00 format
used by REGEDIT on Windows 2000 and later.

Type regexport.pl on its own to see the help:

    regexport.pl <filename> [subkey] [-r]
        -r or --recurse     traverse all child keys from the root key
                            or the subkey specified

Values are always shown for each key displayed.

Subkeys are displayed as comments when not recursing.
(Comments are preceded by the ';' character.)

=head2 regfind.pl

regfind.pl is used to search the keys, values, data, or types
of a registry file for a matching string.

Type regfind.pl on its own to see the help:

    regfind.pl <filename> <search-string> [-k] [-v] [-d] [-t] [-x]
        -k or --key         search key names for a match
        -v or --value       search value names for a match
        -d or --data        search value data for a match
        -t or --type        search value types for a match
        -x or --hexdump     display value data as a hex dump

To search for the string "recent" in the names of any keys or values:

    regfind.pl ntuser.dat recent -kv

To search for the string "administrator" in the data of any values:

    regfind.pl ntuser.dat administrator -d

To list all REG_MULTI_SZ values:

    regfind.pl ntuser.dat -t multi_sz

Search strings are not case-sensitive.

=head2 regmultidiff.pl

regmultidiff.pl can be used to compare multiple registry files
and identify the differences between them.

Type regmultidiff.pl on its own to see the help:

    regmultidiff.pl <file1> <file2> <file3> ... [<subkey>] [-v] [-x] [-a]
        -v or --values      display values
        -x or --hexdump     display value data as a hex dump
        -a or --all         show all keys and values preceding and following
                            any changes

You can limit the comparison by specifying an initial subkey.

=head2 regscan.pl

regscan.pl dumps all the entries in a registry file.
This will include defunct keys and values that are no longer part
of the current active registry.

Type regscan.pl on its own to see the help:

    regscan.pl <filename> [-k] [-v] [-s] [-a] [-p] [-u] [-w]
        -k or --keys        list only 'key' entries
        -v or --values      list only 'value' entries
        -s or --security    list only 'security' entries
        -a or --allocated   list only 'allocated' entries
        -p or --parse-info  show the technical information for an entry
                            instead of the string representation
        -u or --unparsed    show the unparsed on-disk entries as a hex dump
        -w or --warnings    display warnings of invalid keys and values

=head2 regsecurity.pl

regsecurity.pl will display the security information
contained in a registry files.
Only Windows NT registry files contain security information.

Type regsecurity.pl on its own to see the help:

    regsecurity.pl <filename>

=head2 regshell.pl

Provides an interactive command shell
where you navigate through the keys
using 'cd' to change the current key
and 'ls' or 'dir' to list the contents of the current key.

Tab completion of subkey and value names is available.
Names containing spaces are supported by quoting names with " characters.
Note that names are case sensitive.

A filename should be supplied on the command line:

    regshell.pl <filename>

Once regshell.pl is running, type help to see the available commands.

It requires Term::ReadLine to be installed.

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

    regtimeline.pl <filename> [subkey] [-l <number>] [-v] [-x]
        -l or --last        display only the last <number> days
                            of registry activity
        -v or --values      display values
        -x or --hexdump     display value data as a hex dump

=head2 regtree.pl

regtree.pl simply displays the registry as an indented tree,
optionally displaying the values of each key.

Type regtree.pl on its own to see the help:

    regtree.pl <filename> [subkey] [-v]
        -v or --values      display values

=head2 regview.pl

regview.pl is a GTK+ registry viewer.
It displays a tree of registry keys on the left hand side,
a list of values on the right,
and a hex dump of the selected value data at the bottom.

It requires Gtk2-Perl to be installed.
Links to Windows binaries can be found via the project home page at
L<http://gtk2-perl.sourceforge.net/win32/>.

A filename can also be supplied on the command line:

    regview.pl <filename>

=head1 ACKNOWLEDGEMENTS

This would not have been possible without the work of those people who have
analysed and documented the structure of Windows Registry files, namely:
the WINE Project (see misc/registry.c in older releases),
the Samba Project (see utils/editreg.c and utils/profiles.c),
Petter Nordahl-Hagen (see chntpw's ntreg.h),
and B.D. (see WinReg.txt).

I'm grateful to those who have sent me their thanks.

=head1 AUTHOR

James Macfarlane, E<lt>jmacfarla@cpan.orgE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006,2007,2008,2009 by James Macfarlane

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

THIS PACKAGE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION,
THE IMPLIED WARRANTIES OF MERCHANTIBILITY AND FITNESS
FOR A PARTICULAR PURPOSE.

=cut
