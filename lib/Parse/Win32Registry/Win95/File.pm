package Parse::Win32Registry::Win95::File;

use strict;
use warnings;

use Parse::Win32Registry qw(iso8601);
use Parse::Win32Registry::Win95::Key;

use Carp;

use constant OFFSET_TO_RGKN_BLOCK => 0x20;
use constant RGKN_ENTRY_SIZE => 28;

sub new {
    my $class = shift; 
    my $filename = shift or croak "No filename specified";

    open my $regfile, "<", $filename or croak "Unable to open '$filename': $!";

    # CREG Header
    # 0x00 dword = 'CREG' signature
    # 0x04 dword = some kind of version?
    # 0x08 dword = offset to first rgdb block
    # 0x0c
    # 0x10 word  = number of rgdb blocks

    sysread($regfile, my $creg_header, 32);
    if (!defined($creg_header) || length($creg_header) != 32) {
        croak "Could not read registry file header\n";
    }

    my $creg_sig = unpack("a4", $creg_header);
    if ($creg_sig ne "CREG") {
        croak "Invalid registry file signature\n";
    }

    # RGKN Block Header
    # 0x0 dword = 'RGKN' signature
    # 0x4 dword = size of RGKN block
    # 0x8 dword = offset to root key entry (relative to start of RGKN)

    sysseek($regfile, OFFSET_TO_RGKN_BLOCK, 0);
    sysread($regfile, my $rgkn_header, 32);
    if (!defined($rgkn_header) || length($rgkn_header) != 32) {
        croak "Could not read RGKN header at offset ",
            sprintf("0x%x\n", OFFSET_TO_RGKN_BLOCK);
    }
    
    my ($rgkn_sig,
        $rgkn_block_size,
        $offset_to_root_key) = unpack("a4VV", $rgkn_header);
    if ($rgkn_sig ne "RGKN") {
        croak "Invalid RGKN block signature at offset ",
            sprintf("0x%x\n", OFFSET_TO_RGKN_BLOCK);
    }

    $offset_to_root_key += OFFSET_TO_RGKN_BLOCK;

    my $self = {};

    $self->{_regfile} = $regfile;
    $self->{_offset_to_root_key} = $offset_to_root_key;

    bless $self, $class;

    return $self;
}

sub get_root_key {
    my $self = shift;

    my $regfile = $self->{_regfile};
    my $offset_to_root_key = $self->{_offset_to_root_key};

    my $root_key = Parse::Win32Registry::Win95::Key->new($regfile,
                                                         $offset_to_root_key);
    return $root_key;
}

sub get_timestamp {
    return undef;
}

sub get_timestamp_as_string {
    return iso8601(undef);
}

sub dump_file {
    my $self = shift;

    my $regfile = $self->{_regfile};

    ## DUMP CREG HEADER
    sysseek($regfile, 0, 0);
    sysread($regfile, my $creg_header, 0x20);
    if (!defined($creg_header) || length($creg_header) != 0x20) {
        print "end of data\n";
        return;
    }

    my ($creg_sig,
        $offset_to_first_rgdb_block,
        $num_rgdb_blocks) = unpack("a4x4Vx4v", $creg_header);
    print "File signature = '$creg_sig'\n";
    printf "Offset to first RGDB block = 0x%x\n", $offset_to_first_rgdb_block;
    print "Number of RGDB blocks = $num_rgdb_blocks\n";

    ## DUMP RGKN HEADER
    sysseek($regfile, OFFSET_TO_RGKN_BLOCK, 0);
    sysread($regfile, my $rgkn_header, 0x20);
    if (!defined($rgkn_header) || length($rgkn_header) != 0x20) {
        print "end of data\n";
        return;
    }

    my ($rgkn_sig,
        $rgkn_block_size,
        $offset_to_root_key) = unpack("a4VV", $rgkn_header);
    print "RGKN signature = '$rgkn_sig'\n";
    printf "RGKN block size = 0x%x\n", $rgkn_block_size;
    printf "Offset to root key = 0x%x\n", $offset_to_root_key;

    ## DUMP ALL KEY ENTRIES FROM RGKN BLOCK
    my $rgkn_entry_count = 0;
    my $offset_to_rgkn_entry = OFFSET_TO_RGKN_BLOCK + $offset_to_root_key;
    while ($offset_to_rgkn_entry - OFFSET_TO_RGKN_BLOCK < $rgkn_block_size) {
        ## DUMP RGKN ENTRY
        sysseek($regfile, $offset_to_rgkn_entry, 0);
        sysread($regfile, my $rgkn_entry, 28);
        if (!defined($rgkn_entry) || length($rgkn_entry) != 28) {
            print "end of data\n";
            return;
        }

        my ($hash,
            $offset_to_parent,
            $offset_to_first_child,
            $offset_to_next_sibling,
            $rgkn_key_id,
            $rgkn_block_num) = unpack("x4Vx4VVVvv", $rgkn_entry);

        $offset_to_parent += OFFSET_TO_RGKN_BLOCK
            if $offset_to_parent != 0xffffffff;
        $offset_to_first_child += OFFSET_TO_RGKN_BLOCK
            if $offset_to_first_child != 0xffffffff;
        $offset_to_next_sibling += OFFSET_TO_RGKN_BLOCK
            if $offset_to_next_sibling != 0xffffffff;

        printf "rgkn key @ 0x%x ", $offset_to_rgkn_entry;
        printf "p=0x%x,c=0x%x,n=0x%x id=0x%x,bn=0x%x\n",
            $offset_to_parent,
            $offset_to_first_child,
            $offset_to_next_sibling,
            $rgkn_key_id,
            $rgkn_block_num;

        $offset_to_rgkn_entry += 28;
        $rgkn_entry_count++;
    }
    print "Number of RGKN entries = $rgkn_entry_count\n";
}

1;
