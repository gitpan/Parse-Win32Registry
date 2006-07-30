package Parse::Win32Registry::WinNT;

use strict;
use warnings;

use Carp;
use Encode;
use POSIX qw(strftime);

use Parse::Win32Registry qw(decode_win32_filetime :REG_);
use Parse::Win32Registry::WinNT::Key;

use constant OFFSET_TO_FIRST_HBIN => 0x1000;

sub new {
    my $class = shift;
    my $filename = shift;

    open my $regfile, "<", $filename or croak "Unable to open $filename: $!";

    sysread($regfile, my $regf_header, 0x30);
    if (!defined($regf_header) || length($regf_header) != 0x30) {
        croak "Could not read registry file header\n";
    }

    my $regf_sig = unpack("a4", $regf_header);
    if ($regf_sig ne "regf") {
        croak "Invalid registry file signature\n";
    }
    
    my $offset_to_first_key = unpack("x36 V", $regf_header);

    sysseek($regfile, OFFSET_TO_FIRST_HBIN + $offset_to_first_key, 0);
    sysread($regfile, my $nk_header, 0x8);
    if (!defined($nk_header) || length($nk_header) != 0x8) {
        croak "Could not read first key",
            sprintf(" at offset 0x%x\n",
                OFFSET_TO_FIRST_HBIN + $offset_to_first_key);
    }

    if (substr($nk_header, 4, 4) eq "nk\x2c\x00") {
        my $self = {};
        $self->{_regfile} = $regfile;
        $self->{_offset_to_root_key} = $offset_to_first_key;
        bless $self, $class;
        return $self;
    }
    else {
        croak "Did not find root key",
            sprintf(" at offset 0x%x\n",
                OFFSET_TO_FIRST_HBIN + $offset_to_first_key);
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

sub dump_file {
    my $self = shift;

    my $regfile = $self->{_regfile};

    sysseek($regfile, 0, 0);
    sysread($regfile, my $regf_header, 0x30);

    my $sig = unpack("a4", $regf_header);
    print "signature = '$sig'\n";
    
    my $lwt = unpack("x12a8", $regf_header);
    print "lwt = ", decode_win32_filetime($lwt), "\n";

    sysread($regfile, my $fname, 0xd0); # is 0xd0 enough?
    $fname = unpack("Z*", decode("UCS-2LE", $fname));
    print "embedded filename = $fname\n";

    my $pause = <>;

    my $offset_to_hbin = OFFSET_TO_FIRST_HBIN;
    while (1) {
        sysseek($regfile, $offset_to_hbin, 0);
        sysread($regfile, my $hbin_header, 0x20);

        # 0x00 dword = 'hbin' signature
        # 0x04 dword = offset from 0x1000 (start of first hbin) to this hbin
        # 0x08 dword = size of this hbin / relative offset to next hbin

        my ($sig,
            $offset_from_first_hbin,
            $size_of_hbin) = unpack("a4VV", $hbin_header);

        # abort if no signature found; could also check if $size_of_hbin == 0?
        if ($sig eq "hbin") {
            printf "found hbin at 0x%x ", $offset_to_hbin;
            printf "offset_from_first_hbin=0x%x size_of_hbin=0x%x\n",
                $offset_from_first_hbin,
                $size_of_hbin;
        }
        else {
            print "no hbin found - finishing...\n";
            last;
        }

        my $offset = 0x20; # offset to item; begins after hbin header
        while ($offset < $size_of_hbin) {
            sysseek($regfile, $offset_to_hbin + $offset, 0);
            sysread($regfile, my $header, 8);

            my ($size, $sig) = unpack("Va2", $header);

            my $status = "positive";
            if ($size > 0x7fffffff) {
                $status = "negative";
                $size = (0xffffffff - $size) + 1;
            }

            print "  ";
            if ($sig eq "nk") {
                printf "found $sig (size=0x%x, $status) at 0x%x\n",
                    $size, $offset;
            }
            elsif ($sig eq "vk") {
                printf "found $sig (size=0x%x, $status) at 0x%x\n",
                    $size, $offset;
            }
            elsif ($sig eq "lh" || $sig eq "lf"
                || $sig eq "li" || $sig eq "ri") {
                printf "found $sig (size=0x%x, $status) at 0x%x\n",
                    $size, $offset;
            }
            elsif ($sig eq "sk") {
                printf "found $sig (size=0x%x, $status) at 0x%x\n",
                    $size, $offset;
            }
            else {
                printf "found ?? (size=0x%x, $status) at 0x%x\n",
                    $size, $offset; 
            }

            last if $size == 0;
            $offset += $size;
        }

        # jump to next hbin
        $offset_to_hbin += $size_of_hbin;
    }
}

1;
