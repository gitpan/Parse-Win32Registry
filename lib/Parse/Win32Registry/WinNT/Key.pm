package Parse::Win32Registry::WinNT::Key;

use strict;
use warnings;

use base qw(Parse::Win32Registry::Key);

use Carp;
use Parse::Win32Registry::Base qw(:all);
use Parse::Win32Registry::WinNT::Value;
use Parse::Win32Registry::WinNT::Security;

use constant OFFSET_TO_FIRST_HBIN => 0x1000;
use constant NK_HEADER_LENGTH => 0x50;

sub new {
    my $class = shift;
    my $regfile = shift;
    my $offset = shift; # offset to nk record relative to start of file
    my $parent_key_path = shift; # parent key path (optional)

    croak "Missing registry file" if !defined $regfile;
    croak "Missing offset" if !defined $offset;

    # when errors are encountered
    my $whereabouts = defined($parent_key_path)
                    ? " (a subkey of '$parent_key_path')"
                    : "";

    if (0) {
        warnf("NEW KEY at 0x%x%s", $offset, $whereabouts);
    }

    my $fh = $regfile->{_filehandle};
    croak "Missing filehandle" if !defined $fh;

    # 0x00 dword = key length (as negative number)
    # 0x04 word  = 'nk' signature
    # 0x06 word  = flags
    # 0x08 qword = timestamp
    # 0x14 dword = offset to parent
    # 0x18 dword = number of subkeys
    # 0x20 dword = offset to subkey list (lf, lh, ri, li)
    # 0x28 dword = number of values
    # 0x2c dword = offset to value list
    # 0x30 dword = offset to security
    # 0x34 dword = offset to class name
    # 0x4c word  = key name length
    # 0x4e word  = class name length
    # 0x50       = key name [for name length bytes]

    # Extracted offsets are always relative to first HBIN

    sysseek($fh, $offset, 0);
    my $bytes_read = sysread($fh, my $nk_header, NK_HEADER_LENGTH);
    if ($bytes_read != NK_HEADER_LENGTH) {
        warnf("Could not read key at 0x%x%s", $offset, $whereabouts);
        return;
    }

    my ($length,
        $sig,
        $flags,
        $timestamp,
        $offset_to_parent,
        $num_subkeys,
        $offset_to_subkey_list,
        $num_values,
        $offset_to_value_list,
        $offset_to_security,
        $offset_to_class_name,
        $name_length,
        $class_name_length,
        ) = unpack("Va2va8x4VVx4Vx4VVVVx20vv", $nk_header);

    $offset_to_parent += OFFSET_TO_FIRST_HBIN
        if $offset_to_parent != 0xffffffff;
    $offset_to_subkey_list += OFFSET_TO_FIRST_HBIN
        if $offset_to_subkey_list != 0xffffffff;
    $offset_to_value_list += OFFSET_TO_FIRST_HBIN
        if $offset_to_value_list != 0xffffffff;
    $offset_to_security += OFFSET_TO_FIRST_HBIN
        if $offset_to_security != 0xffffffff;
    $offset_to_class_name += OFFSET_TO_FIRST_HBIN
        if $offset_to_class_name != 0xffffffff;

    my $allocated = 0;
    if ($length > 0x7fffffff) {
        $allocated = 1;
        $length = (0xffffffff - $length) + 1;
    }
    # allocated should be true

    if ($sig ne "nk") {
        warnf("Invalid signature for key at 0x%x%s", $offset, $whereabouts);
        return;
    }

    $bytes_read = sysread($fh, my $name, $name_length);
    if ($bytes_read != $name_length) {
        warnf("Could not read name for key at 0x%x%s", $offset, $whereabouts);
        return;
    }

    my $key_path = (defined $parent_key_path)
                 ? "$parent_key_path\\$name"
                 : "$name";
    $whereabouts = sprintf(" for key '%s' at 0x%x", $key_path, $offset);

    my $class_name;
    if ($offset_to_class_name != 0xffffffff) {
        sysseek($fh, $offset_to_class_name + 4, 0);
        $bytes_read = sysread($fh, $class_name, $class_name_length);
        if ($bytes_read != $class_name_length) {
            warnf("Could not read class name at 0x%x%s",
                $offset_to_class_name, $whereabouts);
            $class_name = undef;
        }
        else {
            $class_name = unpack_unicode_string($class_name);
        }
    }

    my $self = {};
    $self->{_regfile} = $regfile;
    $self->{_offset} = $offset;
    $self->{_length} = $length;
    $self->{_allocated} = $allocated;
    $self->{_tag} = $sig;
    $self->{_name} = $name;
    $self->{_name_length} = $name_length;
    $self->{_key_path} = $key_path;
    $self->{_flags} = $flags;
    $self->{_offset_to_parent} = $offset_to_parent;
    $self->{_num_subkeys} = $num_subkeys;
    $self->{_offset_to_subkey_list} = $offset_to_subkey_list;
    $self->{_num_values} = $num_values;
    $self->{_offset_to_value_list} = $offset_to_value_list;
    $self->{_timestamp} = unpack_windows_time($timestamp);
    $self->{_offset_to_security} = $offset_to_security;
    $self->{_offset_to_class_name} = $offset_to_class_name;
    $self->{_class_name_length} = $class_name_length;
    $self->{_class_name} = $class_name;
    bless $self, $class;

    return $self;
}

sub get_timestamp {
    my $self = shift;

    return $self->{_timestamp};
}

sub get_timestamp_as_string {
    my $self = shift;

    return iso8601($self->get_timestamp);
}

sub get_class_name {
    my $self = shift;

    return $self->{_class_name};
}

sub is_root {
    my $self = shift;

    my $flags = $self->{_flags};
    return $flags == 0x2c || $flags == 0xac;
}

sub get_parent {
    my $self = shift;

    my $regfile = $self->{_regfile};
    croak "Missing registry file" if !defined $regfile;
    my $offset_to_parent = $self->{_offset_to_parent};
    croak "Missing offset to parent" if !defined $offset_to_parent;
    my $key_path = $self->{_key_path};

    return if $self->is_root;

    my $parent_key_path;
    my @keys = split /\\/, $key_path, -1;
    if (@keys > 2) {
        $parent_key_path = join("\\", @keys[0..$#keys-2]);
    }

    return Parse::Win32Registry::WinNT::Key->new($regfile,
                                                 $offset_to_parent,
                                                 $parent_key_path);
}

sub get_security {
    my $self = shift;

    my $regfile = $self->{_regfile};
    my $offset_to_security = $self->{_offset_to_security};
    my $key_path = $self->{_key_path};

    if ($offset_to_security == 0xffffffff) {
        return;
    }

    return Parse::Win32Registry::WinNT::Security->new($regfile,
                                                      $offset_to_security,
                                                      $key_path);
}

sub as_string {
    my $self = shift;

    my $string = $self->get_path . " [" . $self->get_timestamp_as_string . "]";
    return $string;
}

sub parse_info {
    my $self = shift;

    my $info = sprintf '0x%x,%d,%d nk "%s" par=0x%x keys=%d,0x%x vals=%d,0x%x',
        $self->{_offset},
        $self->{_allocated},
        $self->{_length},
        $self->{_name},
        $self->{_offset_to_parent},
        $self->{_num_subkeys}, $self->{_offset_to_subkey_list},
        $self->{_num_values}, $self->{_offset_to_value_list};
    $info .= sprintf ' sec=0x%x', $self->{_offset_to_security};
    if (defined $self->{_class_name}) {
        $info .= sprintf ' cls=0x%x,%d bytes',
            $self->{_offset_to_class_name}, $self->{_class_name_length};
    }
    else {
        $info .= sprintf ' cls=0x%x',
            $self->{_offset_to_class_name};
    }
    return $info;
}

sub _get_offsets_to_subkeys {
    my $self = shift;

    # Offset is passed as a parameter for recursive lists such as 'ri'
    my $offset_to_subkey_list = shift || $self->{_offset_to_subkey_list};
    croak "Missing offset to subkey list" if !defined $offset_to_subkey_list;

    my $regfile = $self->{_regfile};
    croak "Missing registry file" if !defined $regfile;
    my $fh = $regfile->{_filehandle};
    croak "Missing filehandle" if !defined $fh;

    return if $offset_to_subkey_list == 0xffffffff
           || $self->{_num_subkeys} == 0;

    # when errors are encountered
    my $key_path = $self->{_key_path};
    my $offset = $self->{_offset};
    my $whereabouts = "";
    if (defined $offset && defined $key_path) {
        $whereabouts = sprintf(" for key '%s' at 0x%x", $key_path, $offset);
    }
    elsif (defined $offset) {
        $whereabouts = sprintf(" for key at 0x%x", $offset);
    }

    sysseek($fh, $offset_to_subkey_list, 0);
    my $bytes_read = sysread($fh, my $subkey_list_header, 8);
    if ($bytes_read != 8) {
        warnf("Could not read subkey list header at 0x%x%s",
            $offset_to_subkey_list, $whereabouts);
        return;
    }

    # 0x00 dword = subkey list length (as negative number)
    # 0x04 word  = 'lf' signature
    # 0x06 word  = number of entries
    # 0x08 dword = offset to 1st subkey
    # 0x0c dword = first four characters of the key name
    # 0x10 dword = offset to 2nd subkey
    # 0x14 dword = first four characters of the key name
    # ...

    # 0x00 dword = subkey list length (as negative number)
    # 0x04 word  = 'lh' signature
    # 0x06 word  = number of entries
    # 0x08 dword = offset to 1st subkey
    # 0x0c dword = hash of the key name
    # 0x10 dword = offset to 2nd subkey
    # 0x14 dword = hash of the key name
    # ...

    # 0x00 dword = subkey list length (as negative number)
    # 0x04 word  = 'ri' signature
    # 0x06 word  = number of entries in ri list
    # 0x08 dword = offset to 1st lf/lh/li list
    # 0x0c dword = offset to 2nd lf/lh/li list
    # 0x10 dword = offset to 3rd lf/lh/li list
    # ...

    # 0x00 dword = subkey list length (as negative number)
    # 0x04 word  = 'li' signature
    # 0x06 word  = number of entries in li list
    # 0x08 dword = offset to 1st subkey
    # 0x0c dword = offset to 2nd subkey
    # ...

    # Extracted offsets are always relative to first HBIN

    my @offsets_to_subkeys = ();

    my ($length,
        $sig,
        $num_entries,
        ) = unpack("Va2v", $subkey_list_header);

    my $subkey_list_length;
    if ($sig eq "lf" || $sig eq "lh") {
        $subkey_list_length = 2 * 4 * $num_entries;
    }
    elsif ($sig eq "ri" || $sig eq "li") {
        $subkey_list_length = 4 * $num_entries;
    }
    else {
        warnf("Invalid signature for subkey list at 0x%x%s",
            $offset_to_subkey_list, $whereabouts);
        return;
    }

    $bytes_read = sysread($fh, my $subkey_list, $subkey_list_length);
    if ($bytes_read != $subkey_list_length) {
        warnf("Could not read subkey list at 0x%x%s",
            $offset_to_subkey_list, $whereabouts);
        return;
    }

    if ($sig eq "lf") {
        for (my $i = 0; $i < $num_entries; $i++) {
            my ($offset, $str) = unpack("VV", substr($subkey_list, 8 * $i, 8));
            push @offsets_to_subkeys, OFFSET_TO_FIRST_HBIN + $offset;
        }
    }
    elsif ($sig eq "lh") {
        for (my $i = 0; $i < $num_entries; $i++) {
            my ($offset, $hash) = unpack("VV", substr($subkey_list, 8 * $i, 8));
            push @offsets_to_subkeys, OFFSET_TO_FIRST_HBIN + $offset;
        }
    }
    elsif ($sig eq "ri") {
        foreach my $offset (unpack("V$num_entries", $subkey_list)) {
            $self->{_indirect_offsets}{$offset} = 1;
            my $offsets_ref = $self->_get_offsets_to_subkeys(OFFSET_TO_FIRST_HBIN + $offset);
            if (defined $offsets_ref && ref $offsets_ref eq 'ARRAY') {
                push @offsets_to_subkeys, @{ $offsets_ref };
            }
        }
    }
    elsif ($sig eq "li") {
        foreach my $offset (unpack("V$num_entries", $subkey_list)) {
            push @offsets_to_subkeys, OFFSET_TO_FIRST_HBIN + $offset;
        }
    }

    return \@offsets_to_subkeys;
}

sub get_subkey_iterator {
    my $self = shift;

    my $regfile = $self->{_regfile};
    croak "Missing registry file" if !defined $regfile;
    my $key_path = $self->{_key_path};

    if (0) {
        my $offset = $self->{_offset};
        my $whereabouts = defined($key_path) ? " ('$key_path')" : '';
        warnf("ITERATING SUBKEYS of 0x%x%s", $offset, $whereabouts);
    }

    my @offsets_to_subkeys = ();
    if ($self->{_num_subkeys} > 0) {
        my $offsets_to_subkeys_ref = $self->_get_offsets_to_subkeys;
        if (defined $offsets_to_subkeys_ref) {
            @offsets_to_subkeys = @{$self->_get_offsets_to_subkeys};
        }
    }

    return Parse::Win32Registry::Iterator->new(sub {
        while (defined(my $offset_to_subkey = shift @offsets_to_subkeys)) {
            my $subkey = Parse::Win32Registry::WinNT::Key->new($regfile, $offset_to_subkey, $key_path);
            if (defined $subkey) {
                return $subkey;
            }
        }
        return; # no more offsets to subkeys
    });
}

sub _get_offsets_to_values {
    my $self = shift;

    my $regfile = $self->{_regfile};
    croak "Missing registry file" if !defined $regfile;
    my $fh = $regfile->{_filehandle};
    croak "Missing filehandle" if !defined $fh;
    my $offset_to_value_list = $self->{_offset_to_value_list};
    croak "Missing offset to value list" if !defined $offset_to_value_list;

    my $num_values = $self->{_num_values};
    return if $num_values == 0;
    # Actually, this could probably just fall through
    # as unpack("x4V0", ...) would return an empty array.

    # when errors are encountered
    my $key_path = $self->{_key_path};
    my $offset = $self->{_offset};
    my $whereabouts = "";
    if (defined $offset && defined $key_path) {
        $whereabouts = sprintf(" for key '%s' at 0x%x", $key_path, $offset);
    }
    elsif (defined $offset) {
        $whereabouts = sprintf(" for key at 0x%x", $offset);
    }

    my @offsets_to_values = ();

    # 0x00 dword = value list length (as negative number)
    # 0x04 dword = 1st offset
    # 0x08 dword = 2nd offset
    # ...

    # Extracted offsets are always relative to first HBIN

    sysseek($fh, $offset_to_value_list, 0);
    my $value_list_length = 0x4 + $num_values * 4;
    my $bytes_read = sysread($fh, my $value_list, $value_list_length);
    if ($bytes_read != $value_list_length) {
        warnf("Could not read value list at 0x%x%s",
            $offset_to_value_list, $whereabouts);
        return;
    }

    foreach my $offset (unpack("x4V$num_values", $value_list)) {
        push @offsets_to_values, OFFSET_TO_FIRST_HBIN + $offset;
    }

    return \@offsets_to_values;
}

sub get_value_iterator {
    my $self = shift;

    my $regfile = $self->{_regfile};
    croak "Missing registry file" if !defined $regfile;
    my $key_path = $self->{_key_path};

    my $offset = $self->{_offset};
    my $whereabouts = defined($key_path) ? " ('$key_path')" : '';
    if (0) {
        warnf("ITERATING VALUES of 0x%x%s", $offset, $whereabouts);
    }

    my @offsets_to_values = ();
    if ($self->{_num_values} > 0) {
        my $offsets_to_values_ref = $self->_get_offsets_to_values;
        if (defined $offsets_to_values_ref) {
            @offsets_to_values = @{$self->_get_offsets_to_values};
        }
    }

    return Parse::Win32Registry::Iterator->new(sub {
        while (defined(my $offset_to_value = shift @offsets_to_values)) {
            my $value = Parse::Win32Registry::WinNT::Value->new($regfile, $offset_to_value, $key_path);
            if (defined $value) {
                return $value;
            }
        }
        return; # no more offsets to values
    });
}

1;
