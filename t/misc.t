use strict;
use warnings;

use Test::More 'no_plan';
use Data::Dumper;
use Encode;
use Time::Local qw(timegm);
use Parse::Win32Registry qw(
    convert_filetime_to_epoch_time
    iso8601
    hexdump
    unpack_string
    unpack_unicode_string
    unpack_windows_time
    formatted_octets
);

$Data::Dumper::Useqq = 1;
$Data::Dumper::Terse = 1;
$Data::Dumper::Indent = 0;

# time tests
my @time_tests = (
    ["\x00\x00\x00\x00\x00\x00\x00\x00", undef,      '(undefined)'],
    #["\x80\xe9\xa5\xd4\xde\xb1\x9d\x01", -1,         '1969-12-31T23:59:59Z'],
    ["\x80\xe9\xa5\xd4\xde\xb1\x9d\x01", undef,      '(undefined)'],
    ["\x00\x80\x3e\xd5\xde\xb1\x9d\x01", 0,          '1970-01-01T00:00:00Z'],
    ["\x80\x16\xd7\xd5\xde\xb1\x9d\x01", 1,          '1970-01-01T00:00:01Z'],
    ["\x00\x00\x00\x00\x00\x00\xc1\x01", 993752854,  '2001-06-28T18:27:34Z'],
    ["\x00\x00\x00\x00\x00\x00\xc2\x01", 1021900351, '2002-05-20T13:12:31Z'],
    ["\x00\x00\x00\x00\x00\x00\xc3\x01", 1050047849, '2003-04-11T07:57:29Z'],
    ["\x00\x00\x00\x00\x00\x00\xc4\x01", 1078195347, '2004-03-02T02:42:27Z'],
    ["\x00\x00\x00\x00\x00\x00\xc5\x01", 1106342844, '2005-01-21T21:27:24Z'],
    ["\x00\x00\x00\x00\x00\x00\xc6\x01", 1134490342, '2005-12-13T16:12:22Z'],
    ["\x00\x00\x00\x00\x00\x00\xc7\x01", 1162637840, '2006-11-04T10:57:20Z'],
    ["\x00\x00\x00\x00\x00\x00\xc8\x01", 1190785338, '2007-09-26T05:42:18Z'],
    ["\x00\x00\x00\x00\x00\x00\xc9\x01", 1218932835, '2008-08-17T00:27:15Z'],
    ["\x00\x00\x00\x00\x00\x00\xca\x01", 1247080333, '2009-07-08T19:12:13Z'],
    ["\x00\x00\x00\x00\x00\x00\xcb\x01", 1275227831, '2010-05-30T13:57:11Z'],
    ["\x00\x00\x00\x00\x00\x00\xcc\x01", 1303375328, '2011-04-21T08:42:08Z'],
    ["\x00\x00\x00\x00\x00\x00\xcd\x01", 1331522826, '2012-03-12T03:27:06Z'],
    ["\x00\x00\x00\x00\x00\x00\xce\x01", 1359670324, '2013-01-31T22:12:04Z'],
    ["\x00\x00\x00\x00\x00\x00\xcf\x01", 1387817821, '2013-12-23T16:57:01Z'],
    ["\x00\x53\x0d\xd4\x1e\xfd\xe9\x01", 2147483646, '2038-01-19T03:14:06Z'],
    ["\x80\xe9\xa5\xd4\x1e\xfd\xe9\x01", 2147483647, '2038-01-19T03:14:07Z'],
    #["\x00\x80\x3e\xd5\x1e\xfd\xe9\x01", 2147483648, '2038-01-19T03:14:08Z'],
    ["\x00\x80\x3e\xd5\x1e\xfd\xe9\x01", 2147483648, '(undefined)'],
    #["\x00\x00\x00\x00\x00\x00\x00\x02", 2767045207, '2057-09-06T23:40:07Z'],
    ["\x00\x00\x00\x00\x00\x00\x00\x02", 2767045207, '(undefined)'],
);

foreach my $time_test (@time_tests) {
    my ($packed_filetime, $time, $time_as_string) = @$time_test;
    my $decoded_time = convert_filetime_to_epoch_time($packed_filetime);
    my $filetime_in_hex = unpack("H*", $packed_filetime);
    if (defined($time)) {
        # The test data time is a Unix epoch time 
        # so is adjusted to the local OS's epoch time
        my $epoch_offset = timegm(0, 0, 0, 1, 0, 70);
        $time += $epoch_offset;
        cmp_ok($decoded_time, '==', $time,
            "$filetime_in_hex - convert_filetime_to_epoch_time == $time");
    }
    else {
        ok(!defined($decoded_time),
            "$filetime_in_hex - convert_filetime_to_epoch_time undefined");
    }
    is(iso8601($decoded_time), $time_as_string,
        "$filetime_in_hex - and iso8601 eq '$time_as_string'");

}

my @time_array_tests = (
    [
        "\x00\x00\x00\x00\x00\x00\xc1\x01\x00\x00\x00\x00\x00\x00\xc2\x01",
        [993752854, 1021900351],
        ['2001-06-28T18:27:34Z', '2002-05-20T13:12:31Z'],
    ],
    [
        "\x00\x00\x00\x00\x00\x00\xc1\x01\x00\x00\x00\x00",
        [993752854],
        ['2001-06-28T18:27:34Z'],
    ],
    [
        "\x00\x00\x00\x00\x00\x00\xc1\x01",
        [993752854],
        ['2001-06-28T18:27:34Z'],
    ],
);
foreach my $time_test (@time_array_tests) {
    my ($packed_filetimes, $times, $time_as_strings) = @$time_test;
    my @decoded_times = unpack_windows_time($packed_filetimes);
    @$times = map { $_ + timegm(0, 0, 0, 1, 0, 70) } @$times;
    is_deeply(\@decoded_times, $times,
        'unpack_windows_time - ' . join("|", @$times));
    is_deeply([map { iso8601($_) } @decoded_times], $time_as_strings,
        'unpack_windows_time - ' . join("|", @$time_as_strings));
}


# hexdump and formatted_octets tests

my $small_text = 'Perl';

my $medium_text = 'This library is free software.';

my $large_text = <<EOT;
THIS PACKAGE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION,
THE IMPLIED WARRANTIES OF MERCHANTIBILITY AND FITNESS
FOR A PARTICULAR PURPOSE.
EOT

is(hexdump(), '', 'no hexdump');
is(hexdump(undef), '', 'undef hexdump');
is(hexdump(''), '', 'empty hexdump');

is(hexdump($small_text), <<EOT, 'small hexdump');
       0  50 65 72 6c                                         Perl
EOT

is(hexdump($medium_text), <<EOT, 'medium hexdump');
       0  54 68 69 73  20 6c 69 62  72 61 72 79  20 69 73 20  This library is 
      10  66 72 65 65  20 73 6f 66  74 77 61 72  65 2e        free software.
EOT

is(hexdump($medium_text, 0x2300), <<EOT, 'medium hexdump - offset');
    2300  54 68 69 73  20 6c 69 62  72 61 72 79  20 69 73 20  This library is 
    2310  66 72 65 65  20 73 6f 66  74 77 61 72  65 2e        free software.
EOT

is(hexdump($large_text), <<EOT, 'large hexdump');
       0  54 48 49 53  20 50 41 43  4b 41 47 45  20 49 53 20  THIS PACKAGE IS 
      10  50 52 4f 56  49 44 45 44  20 22 41 53  20 49 53 22  PROVIDED "AS IS"
      20  20 41 4e 44  20 57 49 54  48 4f 55 54  20 41 4e 59   AND WITHOUT ANY
      30  20 45 58 50  52 45 53 53  0a 4f 52 20  49 4d 50 4c   EXPRESS.OR IMPL
      40  49 45 44 20  57 41 52 52  41 4e 54 49  45 53 2c 20  IED WARRANTIES, 
      50  49 4e 43 4c  55 44 49 4e  47 2c 20 57  49 54 48 4f  INCLUDING, WITHO
      60  55 54 20 4c  49 4d 49 54  41 54 49 4f  4e 2c 0a 54  UT LIMITATION,.T
      70  48 45 20 49  4d 50 4c 49  45 44 20 57  41 52 52 41  HE IMPLIED WARRA
      80  4e 54 49 45  53 20 4f 46  20 4d 45 52  43 48 41 4e  NTIES OF MERCHAN
      90  54 49 42 49  4c 49 54 59  20 41 4e 44  20 46 49 54  TIBILITY AND FIT
      a0  4e 45 53 53  0a 46 4f 52  20 41 20 50  41 52 54 49  NESS.FOR A PARTI
      b0  43 55 4c 41  52 20 50 55  52 50 4f 53  45 2e 0a     CULAR PURPOSE..
EOT

is(hexdump(encode("UCS-2LE", $large_text)), <<EOT, 'large hexdump - unicode');
       0  54 00 48 00  49 00 53 00  20 00 50 00  41 00 43 00  T.H.I.S. .P.A.C.
      10  4b 00 41 00  47 00 45 00  20 00 49 00  53 00 20 00  K.A.G.E. .I.S. .
      20  50 00 52 00  4f 00 56 00  49 00 44 00  45 00 44 00  P.R.O.V.I.D.E.D.
      30  20 00 22 00  41 00 53 00  20 00 49 00  53 00 22 00   .".A.S. .I.S.".
      40  20 00 41 00  4e 00 44 00  20 00 57 00  49 00 54 00   .A.N.D. .W.I.T.
      50  48 00 4f 00  55 00 54 00  20 00 41 00  4e 00 59 00  H.O.U.T. .A.N.Y.
      60  20 00 45 00  58 00 50 00  52 00 45 00  53 00 53 00   .E.X.P.R.E.S.S.
      70  0a 00 4f 00  52 00 20 00  49 00 4d 00  50 00 4c 00  ..O.R. .I.M.P.L.
      80  49 00 45 00  44 00 20 00  57 00 41 00  52 00 52 00  I.E.D. .W.A.R.R.
      90  41 00 4e 00  54 00 49 00  45 00 53 00  2c 00 20 00  A.N.T.I.E.S.,. .
      a0  49 00 4e 00  43 00 4c 00  55 00 44 00  49 00 4e 00  I.N.C.L.U.D.I.N.
      b0  47 00 2c 00  20 00 57 00  49 00 54 00  48 00 4f 00  G.,. .W.I.T.H.O.
      c0  55 00 54 00  20 00 4c 00  49 00 4d 00  49 00 54 00  U.T. .L.I.M.I.T.
      d0  41 00 54 00  49 00 4f 00  4e 00 2c 00  0a 00 54 00  A.T.I.O.N.,...T.
      e0  48 00 45 00  20 00 49 00  4d 00 50 00  4c 00 49 00  H.E. .I.M.P.L.I.
      f0  45 00 44 00  20 00 57 00  41 00 52 00  52 00 41 00  E.D. .W.A.R.R.A.
     100  4e 00 54 00  49 00 45 00  53 00 20 00  4f 00 46 00  N.T.I.E.S. .O.F.
     110  20 00 4d 00  45 00 52 00  43 00 48 00  41 00 4e 00   .M.E.R.C.H.A.N.
     120  54 00 49 00  42 00 49 00  4c 00 49 00  54 00 59 00  T.I.B.I.L.I.T.Y.
     130  20 00 41 00  4e 00 44 00  20 00 46 00  49 00 54 00   .A.N.D. .F.I.T.
     140  4e 00 45 00  53 00 53 00  0a 00 46 00  4f 00 52 00  N.E.S.S...F.O.R.
     150  20 00 41 00  20 00 50 00  41 00 52 00  54 00 49 00   .A. .P.A.R.T.I.
     160  43 00 55 00  4c 00 41 00  52 00 20 00  50 00 55 00  C.U.L.A.R. .P.U.
     170  52 00 50 00  4f 00 53 00  45 00 2e 00  0a 00        R.P.O.S.E.....
EOT

is(formatted_octets(), '', 'no formatted_octets');
is(formatted_octets(undef), '', 'undef formatted_octets');
is(formatted_octets(''), "\n", 'empty formatted_octets');

is(formatted_octets($small_text), <<EOT, 'small formatted_octets');
50,65,72,6c
EOT

is(formatted_octets($medium_text), <<EOT, 'medium formatted_octets');
54,68,69,73,20,6c,69,62,72,61,72,79,20,69,73,20,66,72,65,65,20,73,6f,66,74,77,\\
  61,72,65,2e
EOT

is(formatted_octets($medium_text, 70), <<EOT, 'medium formatted_octets - linebreak');
54,68,69,\\
  73,20,6c,69,62,72,61,72,79,20,69,73,20,66,72,65,65,20,73,6f,66,74,77,61,72,\\
  65,2e
EOT

is(formatted_octets($large_text), <<EOT, 'large formatted_octets');
54,48,49,53,20,50,41,43,4b,41,47,45,20,49,53,20,50,52,4f,56,49,44,45,44,20,22,\\
  41,53,20,49,53,22,20,41,4e,44,20,57,49,54,48,4f,55,54,20,41,4e,59,20,45,58,\\
  50,52,45,53,53,0a,4f,52,20,49,4d,50,4c,49,45,44,20,57,41,52,52,41,4e,54,49,\\
  45,53,2c,20,49,4e,43,4c,55,44,49,4e,47,2c,20,57,49,54,48,4f,55,54,20,4c,49,\\
  4d,49,54,41,54,49,4f,4e,2c,0a,54,48,45,20,49,4d,50,4c,49,45,44,20,57,41,52,\\
  52,41,4e,54,49,45,53,20,4f,46,20,4d,45,52,43,48,41,4e,54,49,42,49,4c,49,54,\\
  59,20,41,4e,44,20,46,49,54,4e,45,53,53,0a,46,4f,52,20,41,20,50,41,52,54,49,\\
  43,55,4c,41,52,20,50,55,52,50,4f,53,45,2e,0a
EOT

is(formatted_octets(encode("UCS-2LE", $large_text)), <<EOT, 'large formatted_octets - unicode');
54,00,48,00,49,00,53,00,20,00,50,00,41,00,43,00,4b,00,41,00,47,00,45,00,20,00,\\
  49,00,53,00,20,00,50,00,52,00,4f,00,56,00,49,00,44,00,45,00,44,00,20,00,22,\\
  00,41,00,53,00,20,00,49,00,53,00,22,00,20,00,41,00,4e,00,44,00,20,00,57,00,\\
  49,00,54,00,48,00,4f,00,55,00,54,00,20,00,41,00,4e,00,59,00,20,00,45,00,58,\\
  00,50,00,52,00,45,00,53,00,53,00,0a,00,4f,00,52,00,20,00,49,00,4d,00,50,00,\\
  4c,00,49,00,45,00,44,00,20,00,57,00,41,00,52,00,52,00,41,00,4e,00,54,00,49,\\
  00,45,00,53,00,2c,00,20,00,49,00,4e,00,43,00,4c,00,55,00,44,00,49,00,4e,00,\\
  47,00,2c,00,20,00,57,00,49,00,54,00,48,00,4f,00,55,00,54,00,20,00,4c,00,49,\\
  00,4d,00,49,00,54,00,41,00,54,00,49,00,4f,00,4e,00,2c,00,0a,00,54,00,48,00,\\
  45,00,20,00,49,00,4d,00,50,00,4c,00,49,00,45,00,44,00,20,00,57,00,41,00,52,\\
  00,52,00,41,00,4e,00,54,00,49,00,45,00,53,00,20,00,4f,00,46,00,20,00,4d,00,\\
  45,00,52,00,43,00,48,00,41,00,4e,00,54,00,49,00,42,00,49,00,4c,00,49,00,54,\\
  00,59,00,20,00,41,00,4e,00,44,00,20,00,46,00,49,00,54,00,4e,00,45,00,53,00,\\
  53,00,0a,00,46,00,4f,00,52,00,20,00,41,00,20,00,50,00,41,00,52,00,54,00,49,\\
  00,43,00,55,00,4c,00,41,00,52,00,20,00,50,00,55,00,52,00,50,00,4f,00,53,00,\\
  45,00,2e,00,0a,00
EOT

# unpack_string tests
{
    my @tests = (
        ["",                   ['']],
        ["\0",                 ['']],
        ["\0\0",               ['', '']],
        ["abcde",              ['abcde']],
        ["abcde\0",            ['abcde']],
        ["abcde\0\0",          ['abcde', '']],
        ["abcde\0fghij",       ['abcde', 'fghij']],
        ["abcde\0fghij\0",     ['abcde', 'fghij']],
        ["abcde\0fghij\0\0",   ['abcde', 'fghij', '']],
        ["abcde\0\0fghij",     ['abcde', '', 'fghij']],
        ["abcde\0\0fghij\0",   ['abcde', '', 'fghij']],
        ["abcde\0\0fghij\0\0", ['abcde', '', 'fghij', '']],
    );

    foreach my $test (@tests) {
        my ($string, $list) = @$test;

        my @s1 = unpack_string($string);
        is_deeply(\@s1, $list,
            '@s = unpack_string('.Dumper($string).')');
        my $s1 = unpack_string($string);
        is($s1, $list->[0],
            '$s = unpack_string('.Dumper($string).')');

        my $ucs2 = encode("UCS-2LE", $string);
        my @s2 = unpack_unicode_string($ucs2);
        is_deeply(\@s1, $list,
            '@s = unpack_unicode_string('.Dumper($string).')');
        my $s2 = unpack_unicode_string($ucs2);
        is($s2, $list->[0],
            '$s = unpack_unicode_string('.Dumper($string).')');
    }
}


