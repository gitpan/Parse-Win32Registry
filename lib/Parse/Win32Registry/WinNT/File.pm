package Parse::Win32Registry::WinNT::File;

use strict;
use warnings;

use Carp;
use Encode;

use Parse::Win32Registry qw(convert_filetime_to_epoch_time iso8601);
use Parse::Win32Registry::WinNT::Key;

use constant OFFSET_TO_FIRST_HBIN => 0x1000;

sub new {
    my $class = shift;
    my $filename = shift or croak "No filename specified";

    open my $regfile, "<", $filename or croak "Unable to open '$filename': $!";

    sysread($regfile, my $regf_header, 0x30);
    if (!defined($regf_header) || length($regf_header) != 0x30) {
        croak "Could not read registry file header\n";
    }

    my ($regf_sig, $timestamp) = unpack("a4x8a8", $regf_header);
    if ($regf_sig ne "regf") {
        croak "Invalid registry file signature\n";
    }
    
    my $offset_to_first_key = unpack("x36 V", $regf_header);
    $offset_to_first_key += OFFSET_TO_FIRST_HBIN;

    sysseek($regfile, $offset_to_first_key, 0);
    sysread($regfile, my $nk_header, 0x8);
    if (!defined($nk_header) || length($nk_header) != 0x8) {
        croak "Could not read first key at offset ",
            sprintf("0x%x\n", $offset_to_first_key);
    }

    if (substr($nk_header, 4, 2) eq "nk") {
        my $self = {};
        $self->{_regfile} = $regfile;
        $self->{_offset_to_root_key} = $offset_to_first_key;
        $self->{_timestamp} = convert_filetime_to_epoch_time($timestamp);
        bless $self, $class;
        return $self;
    }
    else {
        croak "Did not find root key at offset ",
            sprintf("0x%x\n", $offset_to_first_key);
    }
}

sub get_root_key {
    my $self = shift;

    my $regfile = $self->{_regfile};
    my $offset_to_root_key = $self->{_offset_to_root_key};

    my $root_key = Parse::Win32Registry::WinNT::Key->new($regfile,
                                                         $offset_to_root_key);
    return $root_key;
}

sub get_timestamp {
    my $self = shift;

    return $self->{_timestamp};
}

sub get_timestamp_as_string {
    my $self = shift;

    return iso8601($self->{_timestamp});
}

sub dump_file {
    my $self = shift;

    my $regfile = $self->{_regfile};

    sysseek($regfile, 0, 0);
    sysread($regfile, my $regf_header, 0x30);
    if (!defined($regf_header) || length($regf_header) != 0x30) {
        print "end of data\n";
        return;
    }

    my ($sig, $timestamp) = unpack("a4x8a8", $regf_header);
    print "File signature = '$sig'\n";
    print "Timestamp = ", iso8601(convert_filetime_to_epoch_time($timestamp)), "\n";

    sysread($regfile, my $embedded_filename, 0x40);
    if (!defined($embedded_filename) || length($embedded_filename) != 0x40) {
        print "end of data\n";
        return;
    }

    $embedded_filename = unpack("Z*", decode("UCS-2LE", $embedded_filename));
    print "Embedded filename = '$embedded_filename'\n";

    my $offset_to_hbin = OFFSET_TO_FIRST_HBIN;
    while (1) {
        sysseek($regfile, $offset_to_hbin, 0);
        sysread($regfile, my $hbin_header, 0x20);
        if (!defined($hbin_header) || length($hbin_header) != 0x20) {
            print "end of data\n";
            return;
        }

        # 0x00 dword = 'hbin' signature
        # 0x04 dword = offset from 0x1000 (start of first hbin) to this hbin
        # 0x08 dword = size of this hbin / relative offset to next hbin

        my ($sig,
            $offset_from_first_hbin,
            $size_of_hbin) = unpack("a4VV", $hbin_header);

        # abort if no signature found; could also check if $size_of_hbin == 0?
        if ($sig eq "hbin") {
            printf "hbin block @ 0x%x ", $offset_to_hbin;
            printf "offset_from_first_hbin=0x%x size_of_hbin=0x%x\n",
                $offset_from_first_hbin,
                $size_of_hbin;
        }
        else {
            print "no hbin found\n";
            last;
        }

        my $offset = 0x20; # offset to item; begins after hbin header
        while ($offset < $size_of_hbin) {
            sysseek($regfile, $offset_to_hbin + $offset, 0);
            sysread($regfile, my $header, 8);
            if (!defined($header) || length($header) != 8) {
                print "end of data\n";
                return;
            }

            my ($size, $sig) = unpack("Va2", $header);

            my $sign = "+";
            if ($size > 0x7fffffff) {
                $sign = "-";
                $size = (0xffffffff - $size) + 1;
            }

            my $hex_sig = unpack("v", $sig);

            print "  ";
            if ($sig eq "nk") {
                printf "0x%04x '%s' @ 0x%x size=0x%x, %s\n",
                    $hex_sig, $sig, $offset, $size, $sign;
            }
            elsif ($sig eq "vk") {
                printf "0x%04x '%s' @ 0x%x size=0x%x, %s\n",
                    $hex_sig, $sig, $offset, $size, $sign;
            }
            elsif ($sig eq "lh" || $sig eq "lf"
                || $sig eq "li" || $sig eq "ri") {
                printf "0x%04x '%s' @ 0x%x size=0x%x, %s\n",
                    $hex_sig, $sig, $offset, $size, $sign;
            }
            elsif ($sig eq "sk") {
                printf "0x%04x '%s' @ 0x%x size=0x%x, %s\n",
                    $hex_sig, $sig, $offset, $size, $sign;
            }
            else {
                printf "0x%04x '..' @ 0x%x size=0x%x, %s\n",
                    $hex_sig, $offset, $size, $sign;
            }

            last if $size == 0;
            $offset += $size;
        }

        # jump to next hbin
        $offset_to_hbin += $size_of_hbin;
    }
}

1;
