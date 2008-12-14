package Parse::Win32Registry::WinNT::Key;

use strict;
use warnings;

use base qw(Parse::Win32Registry::Key);

use Carp;
use Parse::Win32Registry::Base qw(:all);
use Parse::Win32Registry::WinNT::Value;

use constant OFFSET_TO_FIRST_HBIN => 0x1000;

sub new {
    my $class = shift;
    my $regfile = shift;
    my $offset = shift; # offset to nk record relative to start of file
    my $parent_key_path = shift; # parent key path (optional)

    die "unexpected error: undefined regfile" if !defined $regfile;
    die "unexpected error: undefined offset" if !defined $offset;

    # when errors are encountered
    my $whereabouts = (defined $parent_key_path)
                    ? " (a subkey of $parent_key_path)"
                    : "";

    # 0x00 dword = size (as negative number)
    # 0x04 word  = 'nk' signature
    # 0x06 word  = node type
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

    sysseek($regfile, $offset, 0);
    sysread($regfile, my $nk_header, 0x50);
    if (!defined($nk_header) || length($nk_header) != 0x50) {
        log_error("Could not read key at 0x%x%s", $offset, $whereabouts);
        return;
    }

    my ($size,
        $sig,
        $node_type,
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

    if ($sig ne "nk") {
        log_error("Invalid key signature at 0x%x%s", $offset, $whereabouts);
        return;
    }

    if ($node_type !=   0x00 &&
        $node_type !=   0x20 && $node_type != 0x2c &&
        $node_type !=   0x30 &&
        $node_type !=   0xa0 && $node_type != 0xac &&
        $node_type != 0x1020 &&
        $node_type != 0x10a0
    ) {
        log_error("Invalid key node type at 0x%x%s", $offset, $whereabouts);
    }
    
    sysread($regfile, my $name, $name_length);
    if (!defined($name) || length($name) != $name_length) {
        log_error("Could not read key name at 0x%x%s", $offset, $whereabouts);
        return;
    }

    my $key_path = (defined $parent_key_path)
                 ? "$parent_key_path\\$name"
                 : "$name";

    my $class_name;
    if ($offset_to_class_name != 0xffffffff) {
        sysseek($regfile, $offset_to_class_name + 4, 0);
        sysread($regfile, $class_name, $class_name_length);
        if (!defined($class_name) || 
              length($class_name) != $class_name_length) {
            log_error(
                "Could not read class name at 0x%x for key '%s' at 0x%x%s",
                $offset_to_class_name, $name, $offset, $whereabouts);
            return;
        }
        else {
            $class_name = unpack_unicode_string($class_name);
        }
    }

    my $self = {};
    $self->{_regfile} = $regfile;
    $self->{_offset} = $offset;
    $self->{_name} = $name;
    $self->{_name_length} = $name_length;
    $self->{_key_path} = $key_path;
    $self->{_node_type} = $node_type;
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

    return iso8601($self->{_timestamp});
}

sub get_type {
    my $self = shift;

    return $self->{_node_type};
}

sub is_root {
    my $self = shift;

    my $node_type = $self->{_node_type};

    return $node_type == 0x2c || $node_type == 0xac;
}

sub get_parent {
    my $self = shift;

    my $regfile = $self->{_regfile};
    my $offset_to_parent = $self->{_offset_to_parent};

    return if $self->is_root;

    my $parent_key_path;
    my @keys = split /\\/, $self->{_key_path}, -1;
    if (@keys > 2) {
        $parent_key_path = join("\\", @keys[0..$#keys-2]);
    }

    return Parse::Win32Registry::WinNT::Key->new($regfile, $offset_to_parent,
                                                           $parent_key_path);
}

sub get_class_name {
    my $self = shift;

    return $self->{_class_name};
}

sub as_string {
    my $self = shift;

    return $self->get_path . " [" . $self->get_timestamp_as_string . "]";
}

sub print_summary {
    my $self = shift;

    print $self->as_string, "\n";
}

sub parse_info {
    my $self = shift;

    my $string = sprintf 'nk=0x%x "%s" par=0x%x keys=%d,0x%x vals=%d,0x%x %s',
        $self->{_offset},
        $self->{_name},
        $self->{_offset_to_parent},
        $self->{_num_subkeys}, $self->{_offset_to_subkey_list},
        $self->{_num_values}, $self->{_offset_to_value_list},
        $self->get_timestamp_as_string;
    if (defined(my $class_name = $self->{_class_name})) {
        $string .= sprintf ' class=0x%x,"%s"',
            $self->{_offset_to_class_name}, $self->{_class_name};
    }
    else {
        $string .= sprintf ' class=0x%x',
            $self->{_offset_to_class_name};
    }

    return $string;
}

sub as_hexdump {
    my $self = shift;
    my $regfile = $self->{_regfile};

    my $hexdump = '';

    sysseek($regfile, $self->{_offset}, 0);
    sysread($regfile, my $buffer, 0x50 + $self->{_name_length});
    $hexdump .= hexdump($buffer, $self->{_offset});

    sysseek($regfile, $self->{_offset_to_class_name}, 0);
    sysread($regfile, $buffer, 0x4 + $self->{_class_name_length});
    $hexdump .= hexdump($buffer, $self->{_offset_to_class_name});

    return $hexdump;
}

sub get_offsets_to_subkeys {
    my $self = shift;
    my $offset = shift; # only used for recursive lists such as 'ri'
    
    my $regfile = $self->{_regfile};
    my $offset_to_subkey_list = $offset || $self->{_offset_to_subkey_list};

    # when errors are encountered
    my $key_path = $self->{_key_path};
    my $whereabouts = (defined $key_path)
                    ? " (when enumerating subkeys of $key_path)"
                    : "";

    sysseek($regfile, $offset_to_subkey_list, 0);
    sysread($regfile, my $subkey_list_header, 8);
    if (!defined($subkey_list_header) || length($subkey_list_header) != 8) {
        log_error("Could not read subkey list header at 0x%x%s",
            $offset_to_subkey_list, $whereabouts);
        return;
    }

    # 0x00 dword = size (as negative number)
    # 0x04 word  = 'lf' signature
    # 0x06 word  = number of entries
    # 0x08 dword = offset to 1st subkey
    # 0x0c dword = first four characters of the key name
    # 0x10 dword = offset to 2nd subkey
    # 0x14 dword = first four characters of the key name
    # ...

    # 0x00 dword = size (as negative number)
    # 0x04 word  = 'lh' signature
    # 0x06 word  = number of entries
    # 0x08 dword = offset to 1st subkey
    # 0x0c dword = hash of the key name
    # 0x10 dword = offset to 2nd subkey
    # 0x14 dword = hash of the key name
    # ...

    # 0x00 dword = size (as negative number)
    # 0x04 word  = 'ri' signature
    # 0x06 word  = number of entries in ri list
    # 0x08 dword = offset to 1st lf/lh/li list
    # 0x0c dword = offset to 2nd lf/lh/li list
    # 0x10 dword = offset to 3rd lf/lh/li list
    # ...

    # 0x00 dword = size (as negative number)
    # 0x04 word  = 'li' signature
    # 0x06 word  = number of entries in li list
    # 0x08 dword = offset to 1st subkey
    # 0x0c dword = offset to 2nd subkey
    # ...

    # Extracted offsets are always relative to first HBIN
    
    my @offsets_to_subkeys = ();

    my ($size,
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
        log_error("Invalid subkey list signature at 0x%x%s",
            $offset_to_subkey_list, $whereabouts);
        return;
    }

    sysread($regfile, my $subkey_list, $subkey_list_length);
    if (!defined($subkey_list) || length($subkey_list) != $subkey_list_length) {
        log_error("Could not read subkey list at 0x%x%s",
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
            # If get_offsets_to_subkeys returns undef,
            # the subsequent @{ undef } becomes an empty array
            my $offsets = $self->get_offsets_to_subkeys(OFFSET_TO_FIRST_HBIN
                                                        + $offset);
            if (ref $offsets eq 'ARRAY') {
                push @offsets_to_subkeys,
                     @{ $self->get_offsets_to_subkeys(OFFSET_TO_FIRST_HBIN
                                                      + $offset) };
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

sub get_list_of_subkeys {
    my $self = shift;

    my $regfile = $self->{_regfile};
    my $key_path = $self->{_key_path};

    # when errors are encountered
    my $whereabouts = (defined $key_path)
                    ? " (when enumerating subkeys of $key_path)"
                    : "";

    my @subkeys = ();

    if ($self->{_num_subkeys} > 0) {
        my $offsets_to_subkeys_ref = $self->get_offsets_to_subkeys;

        foreach my $offset_to_subkey (@{$offsets_to_subkeys_ref}) {
            if (my $subkey = Parse::Win32Registry::WinNT::Key->new($regfile,
                             $offset_to_subkey, $key_path)) {
                push @subkeys, $subkey;
            }
        }
    }

    return @subkeys;
}

sub get_offsets_to_values {
    my $self = shift;
    
    my $regfile = $self->{_regfile};
    my $offset_to_value_list = $self->{_offset_to_value_list};
    
    my $num_values = $self->{_num_values};
    die "unexpected error: num_values is zero" if $num_values == 0;

    # when errors are encountered
    my $key_path = $self->{_key_path};
    my $whereabouts = (defined $key_path)
                    ? " (when enumerating values of $key_path)"
                    : "";

    my @offsets_to_values = ();
    
    # 0x00 dword = size (as negative number)
    # 0x04 dword = 1st offset
    # 0x08 dword = 2nd offset
    # ...

    # Extracted offsets are always relative to first HBIN
    
    sysseek($regfile, $offset_to_value_list, 0);
    my $value_list_length = 0x4 + $num_values * 4;
    sysread($regfile, my $value_list, $value_list_length);
    if (!defined($value_list) || length($value_list) != $value_list_length) {
        log_error("Could not read value list at 0x%x%s",
            $offset_to_value_list, $whereabouts);
        return;
    }

    foreach my $offset (unpack("x4V$num_values", $value_list)) {
        push @offsets_to_values, OFFSET_TO_FIRST_HBIN + $offset;
    }
    
    return \@offsets_to_values;
}

sub get_list_of_values {
    my $self = shift;

    my $regfile = $self->{_regfile};
    my $key_path = $self->{_key_path};

    my @values = ();

    if ($self->{_num_values} > 0) {
        my $offsets_to_values_ref = $self->get_offsets_to_values;

        foreach my $offset_to_value (@{$offsets_to_values_ref}) {
            if (my $value = Parse::Win32Registry::WinNT::Value->new($regfile,
                            $offset_to_value, $key_path)) {
                push @values, $value;
            }
        }
    }

    return @values;
}

1;
