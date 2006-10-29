use strict;
use warnings;

use Test::More 'no_plan';
#use Test::More tests => 100;

use Parse::Win32Registry qw(:REG_);

die "Incorrect version" if $Parse::Win32Registry::VERSION != '0.24';

# if offset is undef, then filename should be passed as string
# if offset is specified, then filename should be opened and passed as handle,
# followed by offset
# if method is defined, then object should be created and method called

my @tests = (
    ## WIN32REGISTRY ERROR MESSAGES
    [
        "Parse::Win32Registry", 
        undef, undef, '', 
        'No filename specified',
    ],
    [
        "Parse::Win32Registry",
        'nonexistent_file', undef, '', 
        'Unable to open',
    ],
    [
        "Parse::Win32Registry", 
        'empty_file.rf', undef, '', 
        'Could not read registry file header',
    ],
    [
        "Parse::Win32Registry",
        'invalid_regf_header.rf', undef, '',
        'Not a registry file',
    ],
    ## WINNT ERROR MESSAGES
    [
        "Parse::Win32Registry::WinNT", 
        undef, undef, '', 
        'No filename specified',
    ],
    [
        "Parse::Win32Registry::WinNT",
        'nonexistent_file', undef, '', 
        'Unable to open',
    ],
    [
        "Parse::Win32Registry::WinNT", 
        'empty_file.rf', undef, '', 
        'Could not read registry file header',
    ],
    [
        "Parse::Win32Registry::WinNT",
        'invalid_regf_header.rf', undef, '',
        'Invalid registry file signature',
    ],
    [
        "Parse::Win32Registry::WinNT",
        'missing_hbin.rf', undef, '', # or missing_root_key.rf
        'Could not read first key at offset 0x',
    ],
    #[
    #    "Parse::Win32Registry::WinNT", 
    #    'invalid_hbin_header.rf', undef, '', 
    #    'Invalid HBIN signature at offset 0x',
    #],
    [
        "Parse::Win32Registry::WinNT", 
        'invalid_first_key.rf', undef, '', 
        'Did not find root key at offset 0x',
    ],
    ### WINNT::KEY ERROR MESSAGES
    [
        "Parse::Win32Registry::WinNT::Key",
        'empty_file.rf', 0x0, '',
        'Could not read key at offset 0x',
    ],
    [
        "Parse::Win32Registry::WinNT::Key",
        'invalid_nk_signature.rf', 0x0, '',
        'Invalid key signature at offset 0x',
    ],
    [
        "Parse::Win32Registry::WinNT::Key",
        'invalid_nk_node_type.rf', 0x0, '',
        'Invalid key node type at offset 0x',
    ],
    [
        "Parse::Win32Registry::WinNT::Key",
        'missing_nk_name.rf', 0x0, '',
        'Could not read key name at offset 0x',
    ],
    [
        "Parse::Win32Registry::WinNT::Key",
        'missing_subkey_list_header.rf', 0x1020, 'get_list_of_subkeys',
        'Could not read subkey list header at offset 0x',
    ],
    [
        "Parse::Win32Registry::WinNT::Key", 
        'missing_subkey_list.rf', 0x1020, 'get_list_of_subkeys', 
        'Could not read subkey list at offset 0x',
    ],
    [
        "Parse::Win32Registry::WinNT::Key", 
        'missing_value_list.rf', 0x1020, 'get_list_of_values', 
        'Could not read value list at offset 0x',
    ],
    ### WINNT::VALUE ERROR MESSAGES
    [
        "Parse::Win32Registry::WinNT::Value", 
        'empty_file.rf', 0x0, '', 
        'Could not read value at offset 0x',
    ],
    [
        "Parse::Win32Registry::WinNT::Value", 
        'invalid_vk_signature.rf', 0x0, '', 
        'Invalid value signature at offset 0x',
    ],
    [
        "Parse::Win32Registry::WinNT::Value", 
        'missing_vk_name.rf', 0x0, '', 
        'Could not read value name at offset 0x',
    ],
    [
        "Parse::Win32Registry::WinNT::Value", 
        'invalid_vk_inline_data.rf', 0x0, '', 
        'Invalid inline data length at offset 0x',
    ],
    [
        "Parse::Win32Registry::WinNT::Value", 
        'missing_vk_data.rf', 0x0, '', 
        'Could not read data at offset 0x',
    ],
    ### WIN95 ERROR MESSAGES
    [
        "Parse::Win32Registry::Win95", 
        undef, undef, '', 
        'No filename specified',
    ],
    [
        "Parse::Win32Registry::Win95",
        'nonexistent_file', undef, '', 
        'Unable to open',
    ],
    [
        "Parse::Win32Registry::Win95", 
        'empty_file.rf', undef, '', 
        'Could not read registry file header',
    ],
    [
        "Parse::Win32Registry::Win95",
        'invalid_creg_header.rf', undef, '',
        'Invalid registry file signature',
    ],
    [
        "Parse::Win32Registry::Win95",
        'missing_rgkn_header.rf', undef, '',
        'Could not read RGKN header at offset 0x',
    ],
    [
        "Parse::Win32Registry::Win95", 
        'invalid_rgkn_header.rf', undef, '', 
        'Invalid RGKN block signature at offset 0x',
    ],
    [
        "Parse::Win32Registry::Win95", 
        'missing_root_key.rf', undef, 'get_root_key', 
        'Could not read RGKN entry for key at offset 0x',
    ],
    ### WIN95::KEY ERROR MESSAGES
    [
        "Parse::Win32Registry::Win95::Key",
        'empty_file.rf', 0x0, '',
        'Could not read RGKN entry for key at offset 0x',
    ],
    [
        "Parse::Win32Registry::Win95::Key",
        'invalid_rgkn_block_num.rf', 0x5c, '',
        'Invalid RGKN block number for key at offset 0x',
    ],
    [
        "Parse::Win32Registry::Win95::Key",
        'missing_rgdb_header.rf', 0x5c, '',
        'Could not read RGDB block header at offset 0x',
    ],
    [
        "Parse::Win32Registry::Win95::Key",
        'invalid_rgdb_header.rf', 0x5c, '',
        'Invalid RGDB block signature at offset 0x',
    ],
    [
        "Parse::Win32Registry::Win95::Key",
        'missing_rgdb_entry_for_key.rf', 0x5c, '',
        'Could not read RGDB entry for key at offset 0x',
    ],
    [
        "Parse::Win32Registry::Win95::Key",
        'missing_rgdb_entry_name_for_key.rf', 0x5c, '',
        'Could not read RGDB entry name for key at offset 0x',
    ],
    [
        "Parse::Win32Registry::Win95::Key",
        'no_matching_rgdb_entry_for_key.rf', 0x5c, '',
        'Could not find RGDB entry for key at offset 0x',
    ],
    ### WIN95::VALUE ERROR MESSAGES
    [
        "Parse::Win32Registry::Win95::Value",
        'empty_file.rf', 0x0, '',
        'Could not read RGDB entry for value at offset 0x',
    ],
    [
        "Parse::Win32Registry::Win95::Value",
        'missing_rgdb_entry_name_for_value.rf', 0x0, '',
        'Could not read RGDB entry name for value at offset 0x',
    ],
    [
        "Parse::Win32Registry::Win95::Value",
        'missing_rgdb_entry_data_for_value.rf', 0x0, '',
        'Could not read RGDB entry data for value at offset 0x',
    ],
);

foreach my $test (@tests) {
    my ($object_name, $filename, $offset, $method, $error) = @$test;

    if (defined($filename)) {
        $filename = -d 't' ? 't/'.$filename : $filename;
        die "Missing test data file '$filename'"
            if !-f $filename && $filename !~ m/nonexistent/;

        if (defined($offset)) {
            open my $regfile, "<", $filename
                or die "Could not open test data file '$filename': $!";
            
            if ($method) {
                my $object;
                ok(eval '$object = $object_name->new($regfile, $offset)',
                    "$object_name->new('$filename', ...) succeeded");
                ok(!eval '$object->$method',
                    "\$object->$method failed");
            }
            else {
                ok(!eval '$object_name->new($regfile, $offset)',
                    "$object_name->new('$filename', ...) failed");
            }
            
            close $regfile
                or die "Could not close test data file '$filename': $!";
        }
        else {
            if ($method) {
                my $object;
                ok(eval '$object = $object_name->new("$filename")',
                    "$object_name->new('$filename') succeeded");
                ok(!eval '$object->$method',
                    "\$object->$method failed");
            }
            else {
                ok(!eval "$object_name->new('$filename')",
                    "$object_name->new('$filename') failed");
            }
        }
        like($@, qr/$error/, "...with error '$error...'");
    }
    else {
        ok(!eval "$object_name->new", "$object_name->new failed");
        like($@, qr/$error/, "...with error '$error'");
    }
}
