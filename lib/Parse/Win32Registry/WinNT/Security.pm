package Parse::Win32Registry::WinNT::Security;

use strict;
use warnings;

use base qw(Parse::Win32Registry::Entry);

use Carp;
use Parse::Win32Registry::Base qw(:all);

use constant OFFSET_TO_FIRST_HBIN => 0x1000;
use constant SK_HEADER_LENGTH => 0x18;

sub new {
    my $class = shift;
    my $regfile = shift;
    my $offset = shift; # offset to sk record relative to start of file
    my $key_path = shift; # key path (optional)

    croak "Missing registry file" if !defined $regfile;
    croak "Missing offset" if !defined $offset;

    # when errors are encountered
    my $whereabouts = defined($key_path)
                    ? " (for key '$key_path')"
                    : "";

    if (0) {
        warnf("NEW SECURITY at 0x%x%s", $offset, $whereabouts);
    }

    if (defined(my $cache = $regfile->{_security_cache})) {
        if (exists $cache->{$offset}) {
            return $cache->{$offset};
        }
    }

    my $fh = $regfile->{_filehandle};
    croak "Missing filehandle" if !defined $fh;

    # 0x00 dword = security length (as negative number)
    # 0x04 word  = 'sk' signature
    # 0x08 dword = offset to previous sk
    # 0x0c dword = offset to next sk
    # 0x10 dword = ref count
    # 0x14 dword = length of security descriptor
    # 0x18       = start of security descriptor

    # Extracted offsets are always relative to first HBIN

    sysseek($fh, $offset, 0);
    my $bytes_read = sysread($fh, my $sk_header, SK_HEADER_LENGTH);
    if ($bytes_read != SK_HEADER_LENGTH) {
        warnf("Could not read security at 0x%x%s", $offset, $whereabouts);
        return;
    }

    my ($length,
        $sig,
        $offset_to_previous,
        $offset_to_next,
        $ref_count,
        $sd_length,
        ) = unpack("Va2x2VVVV", $sk_header);

    $offset_to_previous += OFFSET_TO_FIRST_HBIN
        if $offset_to_previous != 0xffffffff;
    $offset_to_next += OFFSET_TO_FIRST_HBIN
        if $offset_to_next != 0xffffffff;

    my $allocated = 0;
    if ($length > 0x7fffffff) {
        $allocated = 1;
        $length = (0xffffffff - $length) + 1;
    }
    # allocated should be true

    if ($sig ne "sk") {
        warnf("Invalid signature for security at 0x%x%s",
            $offset, $whereabouts);
        return;
    }

    $bytes_read = sysread($fh, my $sd_data, $sd_length);
    if ($bytes_read != $sd_length) {
        warnf("Could not read security descriptor for security at 0x%x%s",
            $offset, $whereabouts);
        return;
    }

    my $sd = unpack_security_descriptor($sd_data);
    if (!defined $sd) {
        warnf("Invalid security descriptor for security at 0x%x%s",
            $offset, $whereabouts);
        # Abandon security object if security descriptor is invalid
        return;
    }

    my $self = {};
    $self->{_regfile} = $regfile;
    $self->{_offset} = $offset;
    $self->{_length} = $length;
    $self->{_allocated} = $allocated;
    $self->{_tag} = $sig;
    $self->{_offset_to_previous} = $offset_to_previous;
    $self->{_offset_to_next} = $offset_to_next;
    $self->{_ref_count} = $ref_count;
    $self->{_security_descriptor} = $sd;
    bless $self, $class;

    if (defined(my $cache = $regfile->{_security_cache})) {
        $cache->{$offset} = $self;
    }

    return $self;
}

sub get_previous {
    my $self = shift;
    my $regfile = $self->{_regfile};
    my $offset_to_previous = $self->{_offset_to_previous};

    return Parse::Win32Registry::WinNT::Security->new($regfile,
                                                      $offset_to_previous);
}

sub get_next {
    my $self = shift;
    my $regfile = $self->{_regfile};
    my $offset_to_next = $self->{_offset_to_next};

    return Parse::Win32Registry::WinNT::Security->new($regfile,
                                                      $offset_to_next);
}

sub get_reference_count {
    my $self = shift;

    return $self->{_ref_count};
}

sub get_security_descriptor {
    my $self = shift;

    return $self->{_security_descriptor};
}

sub as_string {
    my $self = shift;

    my $string = "(security, no owner)";
    my $sd = $self->{_security_descriptor};
    if (defined $sd) {
        my $owner = $sd->get_owner;
        if (defined $owner) {
            $string = sprintf "(security, owner %s)", $owner->as_string;
        }
    }
    return $string;
}

sub parse_info {
    my $self = shift;

    my $info = sprintf '0x%x,%d,%d sk prev=0x%x,next=0x%x refs=%d',
        $self->{_offset},
        $self->{_allocated},
        $self->{_length},
        $self->{_offset_to_previous},
        $self->{_offset_to_next},
        $self->{_ref_count};
    if (my $sd = $self->get_security_descriptor) {
        if (my $owner = $sd->get_owner) {
            $info .= " owner=" . $owner->as_string;
        }
    }

    return $info;
}

1;
