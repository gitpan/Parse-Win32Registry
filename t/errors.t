use strict;
use warnings;

use Test::More 'no_plan';
use Parse::Win32Registry qw(convert_filetime_to_epoch_time);

my @tests = (
    ### WIN32REGISTRY ERROR MESSAGES
    {
        object => 'Parse::Win32Registry',
        fatal_error => 'No filename specified',
    },
    {
        object => 'Parse::Win32Registry',
        filename => 'nonexistent_file',
        fatal_error => 'Unable to open',
    },
    {
        object => 'Parse::Win32Registry',
        filename => 'empty_file.rf',
        warning => 'Could not read registry file header',
    },
    {
        object => 'Parse::Win32Registry',
        filename => 'invalid_regf_header.rf',
        warning => 'Invalid registry file header',
    },
    ### EXPORTS ERROR MESSAGES
    {
        test => '$result = convert_filetime_to_epoch_time("\0\0\0\0")',
        fatal_error => 'Invalid filetime size',
    },
    ### WINNT::FILE ERROR MESSAGES
    {
        object => 'Parse::Win32Registry::WinNT::File',
        fatal_error => 'No filename specified',
    },
    {
        object => 'Parse::Win32Registry::WinNT::File',
        filename => 'nonexistent_file',
        fatal_error => 'Unable to open',
    },
    {
        object => 'Parse::Win32Registry::WinNT::File',
        filename => 'empty_file.rf',
        warning => 'Could not read registry file header',
    },
    {
        object => 'Parse::Win32Registry::WinNT::File',
        filename => 'invalid_regf_header.rf',
        warning => 'Invalid registry file signature',
    },
    {
        object => 'Parse::Win32Registry::WinNT::File',
        filename => 'missing_hbin_root_key.rf',
        test => '$result = $object->get_root_key',
        warning => 'Could not read key at 0x',
    },
    # The hbin header is not checked, so this error can never occur
    #{
    #    object => 'Parse::Win32Registry::WinNT::File',
    #    filename => 'invalid_hbin_header.rf',
    #    warning => 'Invalid HBIN signature at offset 0x',
    #},
    ### WINNT::KEY ERROR MESSAGES
    {
        object => 'Parse::Win32Registry::WinNT::Key',
        filename => 'empty_file.rf', 
        offset => 0x0,
        warning => 'Could not read key at 0x',
    },
    {
        object => 'Parse::Win32Registry::WinNT::Key',
        filename => 'invalid_nk_signature.rf', 
        offset => 0x0,
        warning => 'Invalid key signature at 0x',
    },
    {
        object => 'Parse::Win32Registry::WinNT::Key',
        filename => 'invalid_nk_node_type.rf',
        offset => 0x0,
        warning => 'Invalid key node type at 0x',
        further_tests => [
            ['defined($object)'],
            ['$object->get_name', '$$$PROTO.HIV'],
            ['$object->{_node_type}', '==', '256'],
        ],
    },
    {
        object => 'Parse::Win32Registry::WinNT::Key',
        filename => 'missing_nk_name.rf',
        offset => 0x0,
        warning => 'Could not read key name at 0x',
    },
    {
        object => 'Parse::Win32Registry::WinNT::Key',
        filename => 'missing_subkey_list_header.rf',
        offset => 0x1020,
        test => '@result = $object->get_list_of_subkeys',
        warning => 'Could not read subkey list header at 0x',
    },
    {
        object => 'Parse::Win32Registry::WinNT::Key',
        filename => 'missing_subkey_list.rf',
        offset => 0x1020,
        test => '@result = $object->get_list_of_subkeys',
        warning => 'Could not read subkey list at 0x',
    },
    {
        object => 'Parse::Win32Registry::WinNT::Key',
        filename => 'missing_value_list.rf',
        offset => 0x1020,
        test => '@result = $object->get_list_of_values',
        warning => 'Could not read value list at 0x',
    },
    {
        object => 'Parse::Win32Registry::WinNT::Key',
        filename => 'winnt_key_tests.rf',
        offset => 0x1020,
        test => '$result = $object->get_subkey(undef)',
        fatal_error => 'No subkey name specified',
    },
    {
        object => 'Parse::Win32Registry::WinNT::Key',
        filename => 'winnt_value_tests.rf',
        offset => 0x1020,
        test => '$result = $object->get_value(undef)',
        fatal_error => 'No value name specified',
    },
    ### WINNT::KEY MULTIPLE ERROR MESSAGES
    {
        object => 'Parse::Win32Registry::WinNT::Key',
        filename => 'winnt_error_tests.rf',
        offset => 0x1080, # key1
        test => '@result = $object->get_list_of_subkeys',
        list_of_warnings => [
        ],
        further_tests => [
            ['@result', '==', 3],
            ['$result[0]->get_name', 'key1'],
            ['$result[1]->get_name', 'key2'],
            ['$result[2]->get_name', 'key3'],
        ],
    },
    {
        object => 'Parse::Win32Registry::WinNT::Key',
        filename => 'winnt_error_tests.rf',
        offset => 0x10d8, # key2
        test => '@result = $object->get_list_of_subkeys',
        further_tests => [
            ['@result', '==', 2],
            ['$result[0]->get_name', 'key1'],
            ['$result[1]->get_name', 'key3'],
        ],
    },
    {
        object => 'Parse::Win32Registry::WinNT::Key',
        filename => 'winnt_error_tests.rf',
        offset => 0x1130, # key3
        test => '@result = $object->get_list_of_subkeys',
        list_of_warnings => [
            'Invalid key signature at 0x',
            'Invalid key signature at 0x',
            'Invalid key signature at 0x',
        ],
    },
    {
        object => 'Parse::Win32Registry::WinNT::Key',
        filename => 'winnt_error_tests.rf',
        offset => 0x1188, # key4
        test => '@result = $object->get_list_of_values',
        list_of_warnings => [
        ],
        further_tests => [
            ['@result', '==', 3],
            ['$result[0]->get_name', 'sz1'],
            ['$result[1]->get_name', 'sz2'],
            ['$result[2]->get_name', 'sz3'],
        ],
    },
    {
        object => 'Parse::Win32Registry::WinNT::Key',
        filename => 'winnt_error_tests.rf',
        offset => 0x11e0, # key5
        test => '@result = $object->get_list_of_values',
        list_of_warnings => [
            'Could not read data at 0x',
        ],
        further_tests => [
            ['@result', '==', 2],
            ['$result[0]->get_name', 'sz1'],
            ['$result[1]->get_name', 'sz3'],
        ],
    },
    {
        object => 'Parse::Win32Registry::WinNT::Key',
        filename => 'winnt_error_tests.rf',
        offset => 0x1238, # key6
        test => '@result = $object->get_list_of_values',
        list_of_warnings => [
            'Could not read data at 0x',
            'Could not read data at 0x',
            'Could not read data at 0x',
        ],
    },
    ### WINNT::VALUE ERROR MESSAGES
    {
        object => 'Parse::Win32Registry::WinNT::Value',
        filename => 'empty_file.rf',
        offset => 0x0,
        warning => 'Could not read value at 0x',
    },
    {
        object => 'Parse::Win32Registry::WinNT::Value',
        filename => 'invalid_vk_signature.rf',
        offset => 0x0,
        warning => 'Invalid value signature at 0x',
    },
    {
        object => 'Parse::Win32Registry::WinNT::Value',
        filename => 'missing_vk_name.rf',
        offset => 0x0,
        warning => 'Could not read value name at 0x',
    },
    {
        object => 'Parse::Win32Registry::WinNT::Value',
        filename => 'invalid_vk_inline_data.rf',
        offset => 0x0,
        warning => 'Invalid inline data length for value \'.*\' at 0x',
        further_tests => [
            ['defined($object)'],
            ['$object->get_name', 'dword1'],
            ['!defined($object->get_data)'],
            ['$object->get_data_as_string', '(invalid data)'],
        ],
    },
    {
        object => 'Parse::Win32Registry::WinNT::Value',
        filename => 'missing_vk_data.rf',
        offset => 0x0,
        warning => 'Could not read data at 0x',
    },
    ### WIN95::FILE ERROR MESSAGES
    {
        object => 'Parse::Win32Registry::Win95::File',
        fatal_error => 'No filename specified',
    },
    {
        object => 'Parse::Win32Registry::Win95::File',
        filename => 'nonexistent_file',
        fatal_error => 'Unable to open',
    },
    {
        object => 'Parse::Win32Registry::Win95::File',
        filename => 'empty_file.rf',
        warning => 'Could not read registry file header',
    },
    {
        object => 'Parse::Win32Registry::Win95::File',
        filename => 'invalid_creg_header.rf',
        warning => 'Invalid registry file signature',
    },
    {
        object => 'Parse::Win32Registry::Win95::File',
        filename => 'missing_rgkn_header.rf',
        warning => 'Could not read RGKN header at 0x',
    },
    {
        object => 'Parse::Win32Registry::Win95::File',
        filename => 'invalid_rgkn_header.rf',
        warning => 'Invalid RGKN block signature at 0x',
    },
    {
        object => 'Parse::Win32Registry::Win95::File',
        filename => 'missing_rgkn_root_key.rf',
        test => '$result = $object->get_root_key',
        warning => 'Could not read RGKN entry for key at 0x',
    },
    ### WIN95::KEY ERROR MESSAGES
    {
        object => 'Parse::Win32Registry::Win95::Key',
        filename => 'empty_file.rf',
        offset => 0x0,
        warning => 'Could not read RGKN entry for key at 0x',
    },
    {
        object => 'Parse::Win32Registry::Win95::Key',
        filename => 'invalid_rgkn_block_num.rf',
        offset => 0x5c,
        warning => 'Invalid RGKN block number for key at 0x',
        further_tests => [
            ['defined($object)'],
            ['$object->get_name', ''],
            ['$object->get_path', ''],
            ['$object->get_list_of_values', '==', 0],
        ],
    },
    {
        object => 'Parse::Win32Registry::Win95::Key',
        filename => 'missing_rgdb_header.rf',
        offset => 0x5c,
        warning => 'Could not read RGDB block header at 0x',
        further_tests => [
            ['defined($object)'],
            ['$object->get_name', ''],
            ['$object->get_path', ''],
            ['$object->get_list_of_values', '==', 0],
        ],
    },
    {
        object => 'Parse::Win32Registry::Win95::Key',
        filename => 'invalid_rgdb_header.rf',
        offset => 0x5c,
        warning => 'Invalid RGDB block signature at 0x',
        further_tests => [
            ['defined($object)'],
            ['$object->get_name', ''],
            ['$object->get_path', ''],
            ['$object->get_list_of_values', '==', 0],
        ],
    },
    {
        object => 'Parse::Win32Registry::Win95::Key',
        filename => 'invalid_rgdb_block_size.rf',
        offset => 0x5c,
        warning => 'Block size of 0x0 smaller than expected',
        further_tests => [
            ['defined($object)'],
            ['$object->get_name', ''],
            ['$object->get_path', ''],
            ['$object->get_list_of_values', '==', 0],
        ],
    },
    {
        object => 'Parse::Win32Registry::Win95::Key',
        filename => 'missing_rgdb_entry_for_key.rf',
        offset => 0x5c,
        warning => 'Could not read RGDB entry for key at 0x',
        further_tests => [
            ['defined($object)'],
            ['$object->get_name', ''],
            ['$object->get_path', ''],
            ['$object->get_list_of_values', '==', 0],
        ],
    },
    {
        object => 'Parse::Win32Registry::Win95::Key',
        filename => 'missing_rgdb_entry_name_for_key.rf',
        offset => 0x5c,
        warning => 'Could not read RGDB entry name for key at 0x',
        further_tests => [
            ['defined($object)'],
            ['$object->get_name', ''],
            ['$object->get_path', ''],
            ['$object->get_list_of_values', '==', 0],
        ],
    },
    {
        object => 'Parse::Win32Registry::Win95::Key',
        filename => 'invalid_rgdb_entry_size.rf',
        offset => 0x78,
        warning => 'Entry size of 0x0 smaller than expected',
        further_tests => [
            ['defined($object)'],
            ['$object->get_name', ''],
            ['$object->get_path', ''],
            ['$object->get_list_of_values', '==', 0],
        ],
    },
    {
        object => 'Parse::Win32Registry::Win95::Key',
        filename => 'no_matching_rgdb_entry_for_key.rf',
        offset => 0x5c,
        warning => 'Could not find RGDB entry for key at 0x',
        further_tests => [
            ['defined($object)'],
            ['$object->get_name', ''],
            ['$object->get_path', ''],
            ['$object->get_list_of_values', '==', 0],
        ],
    },
    {
        object => 'Parse::Win32Registry::Win95::Key',
        filename => 'win95_key_tests.rf',
        offset => 0x40,
        test => '$result = $object->get_subkey(undef)',
        fatal_error => 'No subkey name specified',
    },
    {
        object => 'Parse::Win32Registry::Win95::Key',
        filename => 'win95_value_tests.rf',
        offset => 0x40,
        test => '$result = $object->get_value(undef)',
        fatal_error => 'No value name specified',
    },
    ### WIN95::KEY MULTIPLE ERROR MESSAGES
    {
        object => 'Parse::Win32Registry::Win95::Key',
        filename => 'win95_error_tests.rf',
        offset => 0x5c, # key1
        test => '@result = $object->get_list_of_subkeys',
        list_of_warnings => [
        ],
        further_tests => [
            ['@result', '==', 3],
            ['$result[0]->get_name', 'key1'],
            ['$result[1]->get_name', 'key2'],
            ['$result[2]->get_name', 'key3'],
        ],
    },
    {
        object => 'Parse::Win32Registry::Win95::Key',
        filename => 'win95_error_tests.rf',
        offset => 0x78, # key2
        test => '@result = $object->get_list_of_subkeys',
        list_of_warnings => [
            'Could not read RGDB entry name for key at 0x',
        ],
        further_tests => [
            ['@result', '==', 3],
            ['$result[0]->get_name', 'key1'],
            ['$result[1]->get_name', ''],
            ['$result[2]->get_name', 'key3'],
        ],
    },
    {
        object => 'Parse::Win32Registry::Win95::Key',
        filename => 'win95_error_tests.rf',
        offset => 0x94, # key3
        test => '@result = $object->get_list_of_subkeys',
        list_of_warnings => [
            'Could not read RGDB entry name for key at 0x',
            'Could not read RGDB entry name for key at 0x',
            'Could not read RGDB entry name for key at 0x',
        ],
        further_tests => [
            ['@result', '==', 3],
            ['$result[0]->get_name', ''],
            ['$result[1]->get_name', ''],
            ['$result[2]->get_name', ''],
        ],
    },
    {
        object => 'Parse::Win32Registry::Win95::Key',
        filename => 'win95_error_tests.rf',
        offset => 0xb0, # key4
        test => '@result = $object->get_list_of_values',
        list_of_warnings => [
        ],
        further_tests => [
            ['@result', '==', 3],
            ['$result[0]->get_name', 'sz1'],
            ['$result[1]->get_name', 'sz2'],
            ['$result[2]->get_name', 'sz3'],
        ],
    },
    {
        object => 'Parse::Win32Registry::Win95::Key',
        filename => 'win95_error_tests.rf',
        offset => 0xcc, # key5
        test => '@result = $object->get_list_of_values',
        list_of_warnings => [
            'Could not read RGDB entry data for value at 0x',
            'Skipping further values',
        ],
        further_tests => [
            ['@result', '==', 1],
            ['$result[0]->get_name', 'sz1'],
            #['$result[1]->get_name', 'sz3'],
        ],
    },
    {
        object => 'Parse::Win32Registry::Win95::Key',
        filename => 'win95_error_tests.rf',
        offset => 0xe8, # key6
        test => '@result = $object->get_list_of_values',
        list_of_warnings => [
            'Could not read RGDB entry data for value at 0x',
            'Skipping further values',
        ],
    },
    ### WIN95::VALUE ERROR MESSAGES
    {
        object => 'Parse::Win32Registry::Win95::Value',
        filename => 'empty_file.rf',
        offset => 0x0,
        warning => 'Could not read RGDB entry for value at 0x',
    },
    {
        object => 'Parse::Win32Registry::Win95::Value',
        filename => 'missing_rgdb_entry_name_for_value.rf',
        offset => 0x0,
        warning => 'Could not read RGDB entry name for value at 0x',
    },
    {
        object => 'Parse::Win32Registry::Win95::Value',
        filename => 'missing_rgdb_entry_data_for_value.rf',
        offset => 0x0,
        warning => 'Could not read RGDB entry data for value at 0x',
    },
);

foreach my $test (@tests) {
    my $object_class = $test->{object};
    my $filename = $test->{filename};
    my $offset = $test->{offset};
    my $parent_key = $test->{parent_key};
    my $method_test = $test->{test};
    my $fatal_error = $test->{fatal_error};
    my $warning = $test->{warning};
    my $list_of_warnings = $test->{list_of_warnings};
    my $further_tests = $test->{further_tests};

    if (defined $filename) {
        $filename = -d 't' ? 't/'.$filename : $filename;
        die "Missing test data file '$filename'"
            if !-f $filename && $filename !~ m/nonexistent/;
    }

    # if an offset is given, then a filehandle should be opened for filename
    my $regfile;
    if (defined $offset) {
        open $regfile, "<", $filename
            or die "Could not open test data file '$filename': $!";
    }

    # declare variables used in tests
    my $object;
    my $result;
    my @result;

    my $setup = "";
    my $setup_desc = "";
    if (defined $object_class) {
        #$setup = "\$object = $object_class->new";
        if (defined $filename) {
            if (defined $offset) {
                if (defined $parent_key) {
                    $setup = "\$object = $object_class->new" .
                        "(\$regfile, \$offset, \$parent_key)";
                    $setup_desc = sprintf("\$object = $object_class->new" .
                        "(<$filename>, 0x%x, '$parent_key')", $offset);
                }
                else {
                    $setup = "\$object = $object_class->new" .
                        "(\$regfile, \$offset)";
                    $setup_desc = sprintf("\$object = $object_class->new" .
                        "(<$filename>, 0x%x)", $offset);
                }
            }
            else {
                $setup = "\$object = $object_class->new(\$filename)";
                $setup_desc = "\$object = $object_class->new(<$filename>)";
            }
        }
        else {
            $setup = "\$object = $object_class->new";
            $setup_desc = $setup;
        }
    }
    
    my $eval;
    my $eval_desc;
    if (defined $method_test) {
        if ($setup) {
            # eval $setup
            # ok defined $object or diag $@
            ok eval $setup, "$setup_desc should succeed"
                or diag $@;
        }
        $eval = $method_test;
        $eval_desc = $method_test;
    }
    else {
        $eval = $setup;
        $eval_desc = $setup_desc;
    }
        
    my @caught_warnings = ();
    local $SIG{__WARN__} = sub { push @caught_warnings, shift; };

    if ($further_tests) {
        ok eval $eval, "$eval_desc should succeed";
    }
    else {
        ok !eval $eval, "$eval_desc should fail";
    }
    
    if ($fatal_error) {
        like $@, qr/$fatal_error/, qq{...with fatal error "$fatal_error..."};
    }
    elsif ($warning) {
        my $num_caught = @caught_warnings;
        cmp_ok $num_caught, '==', 1, "...with only one warning";
        my $caught_warning = $caught_warnings[0];
        $caught_warning = '' if !defined $caught_warning;
        like $caught_warning, qr/$warning/, qq{...warning "$warning"};
    }
    elsif ($list_of_warnings) {
        die if ref $list_of_warnings ne 'ARRAY';
        my $num_caught = @caught_warnings;
        my $num_expected = @$list_of_warnings;
        cmp_ok $num_caught, '==', $num_expected,
            "...with $num_expected warnings";
        my $i = 1;
        foreach my $warning (@$list_of_warnings) {
            my $caught_warning = shift @caught_warnings;
            $caught_warning = '' if !defined $caught_warning;
            like $caught_warning, qr/$warning/, qq{...warning $i "$warning"};
            $i++;
        }
    }

    if (defined $further_tests) {
        die if ref $further_tests ne 'ARRAY';
        foreach my $further_test (@$further_tests) {
            my @params = @$further_test;
            if (@params == 1) {
                my $test_desc = "...and $params[0]";
                ok(eval $params[0], $test_desc);
            }
            elsif (@params == 2) {
                my $test_desc = "...and $params[0] eq '$params[1]'";
                is(eval $params[0], $params[1], $test_desc);
            }
            elsif (@params == 3) {
                my $test_desc = $params[1] eq '=='
                  ? "...and $params[0] $params[1] $params[2]"
                  : "...and $params[0] $params[1] '$params[2]'";
                cmp_ok(eval $params[0], $params[1], $params[2],
                    $test_desc);
            }
        }
    }
}
