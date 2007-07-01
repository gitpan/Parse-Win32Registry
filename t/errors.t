use strict;
use warnings;

use Test::More 'no_plan';

use Parse::Win32Registry qw(:REG_ convert_filetime_to_epoch_time);

die 'Incorrect version' if $Parse::Win32Registry::VERSION != '0.30';

# $error_type
use constant WARNING => 0;
use constant FATAL => 1;

# What kind of test is being run?
# TEST_OBJECT_CREATION
# 'class', '',
# TEST_OBJECT_METHOD if FILENAME_SPECIFIED
# 'class', 'method',
# TEST_FUNCTION (should have been imported)
# '', 'method',

# What kind of parameter is passed to the object creation?
# PASS_NOTHING
# undef, undef,
# PASS_FILENAME
# 'filename', undef,
# PASS_FILEHANDLE_AND_OFFSET
# 'filename', <offset>,

# What kind of error should be expected?
# WARNING
# 'error message', WARNING,
# FATAL
# 'error message', FATAL,


my @tests = (
    ## WIN32REGISTRY ERROR MESSAGES
    [
        'Parse::Win32Registry', '',
        undef, undef,
        'No filename specified', FATAL,
    ],
    [
        'Parse::Win32Registry', '', 
        'nonexistent_file', undef,
        'Unable to open', FATAL,
    ],
    [
        'Parse::Win32Registry',  '', 
        'empty_file.rf', undef,
        'Could not read registry file header', FATAL,
    ],
    [
        'Parse::Win32Registry', '', 
        'invalid_regf_header.rf', undef,
        'Not a registry file', FATAL,
    ],
    [
        '', 'convert_filetime_to_epoch_time("\0\0\0\0")', 
        undef, undef,
        'Invalid filetime size', FATAL,
    ],
    ## WINNT::FILE ERROR MESSAGES
    [
        'Parse::Win32Registry::WinNT::File', '',
        undef, undef,
        'No filename specified', FATAL,
    ],
    [
        'Parse::Win32Registry::WinNT::File', '',
        'nonexistent_file', undef,
        'Unable to open', FATAL,
    ],
    [
        'Parse::Win32Registry::WinNT::File', '',
        'empty_file.rf', undef,
        'Could not read registry file header', FATAL,
    ],
    [
        'Parse::Win32Registry::WinNT::File', '',
        'invalid_regf_header.rf', undef,
        'Invalid registry file signature', FATAL,
    ],
    [
        'Parse::Win32Registry::WinNT::File', '',
        'missing_hbin.rf', undef, # or missing_root_key.rf
        'Could not read first key at offset 0x', FATAL,
    ],
    #[
    #    'Parse::Win32Registry::WinNT::File', '',
    #    'invalid_hbin_header.rf', undef,
    #    'Invalid HBIN signature at offset 0x', FATAL,
    #],
    [
        'Parse::Win32Registry::WinNT::File', '',
        'invalid_first_key.rf', undef,
        'Did not find root key at offset 0x', FATAL,
    ],
    ### WINNT::KEY ERROR MESSAGES
    [
        'Parse::Win32Registry::WinNT::Key', '',
        'empty_file.rf', 0x0,
        'Could not read key at offset 0x', FATAL,
    ],
    [
        'Parse::Win32Registry::WinNT::Key', '',
        'invalid_nk_signature.rf', 0x0,
        'Invalid key signature at offset 0x', FATAL,
    ],
    [
        'Parse::Win32Registry::WinNT::Key', '',
        'invalid_nk_node_type.rf', 0x0,
        'Invalid key node type at offset 0x', WARNING,
    ],
    [
        'Parse::Win32Registry::WinNT::Key', '',
        'missing_nk_name.rf', 0x0,
        'Could not read key name at offset 0x', FATAL,
    ],
    [
        'Parse::Win32Registry::WinNT::Key', 'get_list_of_subkeys',
        'missing_subkey_list_header.rf', 0x1020,
        'Could not read subkey list header at offset 0x', FATAL,
    ],
    [
        'Parse::Win32Registry::WinNT::Key', 'get_list_of_subkeys', 
        'missing_subkey_list.rf', 0x1020,
        'Could not read subkey list at offset 0x', FATAL,
    ],
    [
        'Parse::Win32Registry::WinNT::Key', 'get_list_of_values', 
        'missing_value_list.rf', 0x1020,
        'Could not read value list at offset 0x', FATAL,
    ],
    [
        'Parse::Win32Registry::WinNT::Key', 'get_subkey(undef)',
        'winnt_key_tests.rf', 0x1020,
        'No subkey name specified', FATAL,
    ],
    ### WINNT::VALUE ERROR MESSAGES
    [
        'Parse::Win32Registry::WinNT::Value', '', 
        'empty_file.rf', 0x0,
        'Could not read value at offset 0x', FATAL,
    ],
    [
        'Parse::Win32Registry::WinNT::Value', '', 
        'invalid_vk_signature.rf', 0x0,
        'Invalid value signature at offset 0x', FATAL,
    ],
    [
        'Parse::Win32Registry::WinNT::Value', '', 
        'missing_vk_name.rf', 0x0,
        'Could not read value name at offset 0x', FATAL,
    ],
    [
        'Parse::Win32Registry::WinNT::Value', '', 
        'invalid_vk_inline_data.rf', 0x0,
        'Invalid inline data length at offset 0x', FATAL,
    ],
    [
        'Parse::Win32Registry::WinNT::Value', '', 
        'missing_vk_data.rf', 0x0,
        'Could not read data at offset 0x', FATAL,
    ],
    ### WIN95::FILE ERROR MESSAGES
    [
        'Parse::Win32Registry::Win95::File', '', 
        undef, undef,
        'No filename specified', FATAL,
    ],
    [
        'Parse::Win32Registry::Win95::File', '', 
        'nonexistent_file', undef,
        'Unable to open', FATAL,
    ],
    [
        'Parse::Win32Registry::Win95::File', '', 
        'empty_file.rf', undef,
        'Could not read registry file header', FATAL,
    ],
    [
        'Parse::Win32Registry::Win95::File', '',
        'invalid_creg_header.rf', undef,
        'Invalid registry file signature', FATAL,
    ],
    [
        'Parse::Win32Registry::Win95::File', '',
        'missing_rgkn_header.rf', undef,
        'Could not read RGKN header at offset 0x', FATAL,
    ],
    [
        'Parse::Win32Registry::Win95::File', '', 
        'invalid_rgkn_header.rf', undef,
        'Invalid RGKN block signature at offset 0x', FATAL,
    ],
    [
        'Parse::Win32Registry::Win95::File', 'get_root_key', 
        'missing_root_key.rf', undef,
        'Could not read RGKN entry for key at offset 0x', FATAL,
    ],
    ### WIN95::KEY ERROR MESSAGES
    [
        'Parse::Win32Registry::Win95::Key', '',
        'empty_file.rf', 0x0,
        'Could not read RGKN entry for key at offset 0x', FATAL,
    ],
    [
        'Parse::Win32Registry::Win95::Key', '',
        'invalid_rgkn_block_num.rf', 0x5c,
        'Invalid RGKN block number for key at offset 0x', FATAL,
    ],
    [
        'Parse::Win32Registry::Win95::Key', '',
        'missing_rgdb_header.rf', 0x5c,
        'Could not read RGDB block header at offset 0x', FATAL,
    ],
    [
        'Parse::Win32Registry::Win95::Key', '',
        'invalid_rgdb_header.rf', 0x5c,
        'Invalid RGDB block signature at offset 0x', FATAL,
    ],
    [
        'Parse::Win32Registry::Win95::Key', '',
        'missing_rgdb_entry_for_key.rf', 0x5c,
        'Could not read RGDB entry for key at offset 0x', FATAL,
    ],
    [
        'Parse::Win32Registry::Win95::Key', '',
        'missing_rgdb_entry_name_for_key.rf', 0x5c,
        'Could not read RGDB entry name for key at offset 0x', FATAL,
    ],
    [
        'Parse::Win32Registry::Win95::Key', '',
        'no_matching_rgdb_entry_for_key.rf', 0x5c,
        'Could not find RGDB entry for key at offset 0x', FATAL,
    ],
    [
        'Parse::Win32Registry::Win95::Key', 'get_subkey(undef)',
        'win95_key_tests.rf', 0x40,
        'No subkey name specified', FATAL,
    ],
    ### WIN95::VALUE ERROR MESSAGES
    [
        'Parse::Win32Registry::Win95::Value', '',
        'empty_file.rf', 0x0,
        'Could not read RGDB entry for value at offset 0x', FATAL,
    ],
    [
        'Parse::Win32Registry::Win95::Value', '',
        'missing_rgdb_entry_name_for_value.rf', 0x0,
        'Could not read RGDB entry name for value at offset 0x', FATAL,
    ],
    [
        'Parse::Win32Registry::Win95::Value', '',
        'missing_rgdb_entry_data_for_value.rf', 0x0,
        'Could not read RGDB entry data for value at offset 0x', FATAL,
    ],
);

sub create_variable_name {
    my $object_class = shift;

    my $object_name = "";
    if ($object_class =~ m/Value$/) {
        $object_name = "\$value";
    }
    elsif ($object_class =~ m/Key$/) {
        $object_name = "\$key";
    }
    else {
        $object_name = "\$registry";
    }
    return $object_name;
}

sub check_result {
    my ($result, $error_type, $desc) = @_;

    if ($error_type == FATAL) {
        ok(!defined($result), "$desc should fail");
    }
    else {
        ok(defined($result), "$desc should succeed");
    }
}


foreach my $test (@tests) {
    #my ($parameters_passed, $filename, $offset, $test_type, $object_class, $method, $error_type, $error) = @$test;

    my ($object_class, $method, $filename, $offset, $error, $error_type) = @$test;

    my $object_name = create_variable_name($object_class);

    # We want to catch warnings as well as fatal errors...
    my $warning;
    local $SIG{__WARN__} = sub { $warning = shift; };

    my $object; # used in $eval
    my $eval;
    my $desc;

    if (defined($filename)) {
        $filename = -d 't' ? 't/'.$filename : $filename;
        die "Missing test data file '$filename'"
            if !-f $filename && $filename !~ m/nonexistent/;
    }

    my $regfile;
    if (defined($offset)) {
        open $regfile, "<", $filename
            or die "Could not open test data file '$filename': $!";
    }

    if (defined($filename)) {
        if (defined($offset)) {
            if ($method) {
                my $eval0 = '$object = $object_class->new($regfile, $offset)';
                my $desc0 = "$object_name = $object_class->new('$filename', ...)";
                ok(eval $eval0, "$desc0 should succeed");

                $eval = '$object->' . $method;
                $desc = "$object_name->$method";
            }
            else {
                $eval = '$object_class->new($regfile, $offset)';
                $desc = "$object_name = $object_class->new('$filename', ...)";
            }
            
        }
        else {
            if ($method) {
                my $eval0 = '$object = $object_class->new("$filename")';
                my $desc0 = "$object_name = $object_class->new('$filename')";
                ok(eval $eval0, "$desc0 should succeed");
                
                $eval = '$object->' . $method;
                $desc = "$object_name->$method";
            }
            else {
                $eval = "$object_class->new('$filename')";
                $desc = "$object_name = $object_class->new('$filename')";
            }
        }
    }
    else {
        if ($method) {
            $eval = "$object_class::$method";
            $desc = "$object_class::$method";
        }
        else {
            $eval = "$object_class->new";
            $desc = "$object_name = $object_class->new";
        }
    }

    # Eval the object creation/method
    if ($error_type == FATAL) {
        ok(!eval $eval, "$desc should fail");
    }
    else {
        ok(eval $eval, "$desc should succeed");
    }

    # Check the error message caught by the eval
    if ($error_type == FATAL) {
        like($@, qr/$error/, "...with error '$error...'");
    }
    else {
        like($warning, qr/$error/, "...with warning '$error...'");
    }

    if (defined($regfile)) {
        close $regfile
            or die "Could not close test data file '$filename': $!";
    }
}
