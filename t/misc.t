use strict;
use warnings;

use Test::More 'no_plan';
use Encode;
use Time::Local qw(timegm);
use Parse::Win32Registry 0.50 qw(
    hexdump
    format_octets
    convert_filetime_to_epoch_time
    iso8601
    unpack_windows_time
    unpack_string
    unpack_unicode_string
    unpack_guid
);

# hexdump and format_octets tests
my $small_text = 'Perl';

my $medium_text = 'This library is free software.';

my $large_text = <<EOT;
THIS PACKAGE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION,
THE IMPLIED WARRANTIES OF MERCHANTIBILITY AND FITNESS
FOR A PARTICULAR PURPOSE.
EOT

my $full_text = pack("C*", 0..255);

is(hexdump($full_text), <<EOT, 'robust hexdump');
       0  00 01 02 03  04 05 06 07  08 09 0a 0b  0c 0d 0e 0f  ................
      10  10 11 12 13  14 15 16 17  18 19 1a 1b  1c 1d 1e 1f  ................
      20  20 21 22 23  24 25 26 27  28 29 2a 2b  2c 2d 2e 2f   !"#\$\%&'()*+,-./
      30  30 31 32 33  34 35 36 37  38 39 3a 3b  3c 3d 3e 3f  0123456789:;<=>?
      40  40 41 42 43  44 45 46 47  48 49 4a 4b  4c 4d 4e 4f  \@ABCDEFGHIJKLMNO
      50  50 51 52 53  54 55 56 57  58 59 5a 5b  5c 5d 5e 5f  PQRSTUVWXYZ[\\]^_
      60  60 61 62 63  64 65 66 67  68 69 6a 6b  6c 6d 6e 6f  `abcdefghijklmno
      70  70 71 72 73  74 75 76 77  78 79 7a 7b  7c 7d 7e 7f  pqrstuvwxyz{|}~.
      80  80 81 82 83  84 85 86 87  88 89 8a 8b  8c 8d 8e 8f  ................
      90  90 91 92 93  94 95 96 97  98 99 9a 9b  9c 9d 9e 9f  ................
      a0  a0 a1 a2 a3  a4 a5 a6 a7  a8 a9 aa ab  ac ad ae af  ................
      b0  b0 b1 b2 b3  b4 b5 b6 b7  b8 b9 ba bb  bc bd be bf  ................
      c0  c0 c1 c2 c3  c4 c5 c6 c7  c8 c9 ca cb  cc cd ce cf  ................
      d0  d0 d1 d2 d3  d4 d5 d6 d7  d8 d9 da db  dc dd de df  ................
      e0  e0 e1 e2 e3  e4 e5 e6 e7  e8 e9 ea eb  ec ed ee ef  ................
      f0  f0 f1 f2 f3  f4 f5 f6 f7  f8 f9 fa fb  fc fd fe ff  ................
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

is(format_octets(), '', 'no format_octets');
is(format_octets(undef), '', 'undef format_octets');
is(format_octets(''), "", 'empty format_octets');

is(format_octets($small_text)."\n", <<EOT, 'small format_octets');
50,65,72,6c
EOT

is(format_octets($medium_text)."\n", <<EOT, 'medium format_octets');
54,68,69,73,20,6c,69,62,72,61,72,79,20,69,73,20,66,72,65,65,20,73,6f,66,74,77,\\
  61,72,65,2e
EOT

is(format_octets($medium_text, 70)."\n", <<EOT, 'medium format_octets - linebreak');
54,68,69,\\
  73,20,6c,69,62,72,61,72,79,20,69,73,20,66,72,65,65,20,73,6f,66,74,77,61,72,\\
  65,2e
EOT

is(format_octets($large_text)."\n", <<EOT, 'large format_octets');
54,48,49,53,20,50,41,43,4b,41,47,45,20,49,53,20,50,52,4f,56,49,44,45,44,20,22,\\
  41,53,20,49,53,22,20,41,4e,44,20,57,49,54,48,4f,55,54,20,41,4e,59,20,45,58,\\
  50,52,45,53,53,0a,4f,52,20,49,4d,50,4c,49,45,44,20,57,41,52,52,41,4e,54,49,\\
  45,53,2c,20,49,4e,43,4c,55,44,49,4e,47,2c,20,57,49,54,48,4f,55,54,20,4c,49,\\
  4d,49,54,41,54,49,4f,4e,2c,0a,54,48,45,20,49,4d,50,4c,49,45,44,20,57,41,52,\\
  52,41,4e,54,49,45,53,20,4f,46,20,4d,45,52,43,48,41,4e,54,49,42,49,4c,49,54,\\
  59,20,41,4e,44,20,46,49,54,4e,45,53,53,0a,46,4f,52,20,41,20,50,41,52,54,49,\\
  43,55,4c,41,52,20,50,55,52,50,4f,53,45,2e,0a
EOT

is(format_octets(encode("UCS-2LE", $large_text))."\n", <<EOT, 'large format_octets - unicode');
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

# time tests
my @time_tests = (
    [
        "TIME1",
        "\x00\x00\x00\x00\x00\x00\x00\x00",
        undef,
        '(undefined)',
    ],
    [
        "TIME2",
        "\x80\xe9\xa5\xd4\xde\xb1\x9d\x01",
        undef, # -1
        '(undefined)', # '1969-12-31T23:59:59Z'
    ],
    [
        "TIME3",
        "\x00\x80\x3e\xd5\xde\xb1\x9d\x01",
        0,
        '1970-01-01T00:00:00Z',
    ],
    [
        "TIME4",
        "\x80\x16\xd7\xd5\xde\xb1\x9d\x01",
        1,
        '1970-01-01T00:00:01Z',
    ],
    [
        "TIME5",
        "\x00\x00\x00\x00\x00\x00\xc1\x01",
        993752854,
        '2001-06-28T18:27:34Z',
    ],
    [
        "TIME6",
        "\x00\x00\x00\x00\x00\x00\xc2\x01",
        1021900351,
        '2002-05-20T13:12:31Z',
    ],
    [
        "TIME7",
        "\x00\x00\x00\x00\x00\x00\xc3\x01",
        1050047849,
        '2003-04-11T07:57:29Z',
    ],
    [
        "TIME8",
        "\x00\x00\x00\x00\x00\x00\xc4\x01",
        1078195347,
        '2004-03-02T02:42:27Z',
    ],
    [
        "TIME9",
        "\x00\x00\x00\x00\x00\x00\xc5\x01",
        1106342844,
        '2005-01-21T21:27:24Z',
    ],
    [
        "TIME10",
        "\x00\x00\x00\x00\x00\x00\xc6\x01",
        1134490342,
        '2005-12-13T16:12:22Z',
    ],
    [
        "TIME11",
        "\x00\x00\x00\x00\x00\x00\xc7\x01",
        1162637840,
        '2006-11-04T10:57:20Z',
    ],
    [
        "TIME12",
        "\x00\x00\x00\x00\x00\x00\xc8\x01",
        1190785338,
        '2007-09-26T05:42:18Z',
    ],
    [
        "TIME13",
        "\x00\x00\x00\x00\x00\x00\xc9\x01",
        1218932835,
        '2008-08-17T00:27:15Z',
    ],
    [
        "TIME14",
        "\x00\x00\x00\x00\x00\x00\xca\x01",
        1247080333,
        '2009-07-08T19:12:13Z',
    ],
    [
        "TIME15",
        "\x00\x00\x00\x00\x00\x00\xcb\x01",
        1275227831,
        '2010-05-30T13:57:11Z',
    ],
    [
        "TIME16",
        "\x00\x00\x00\x00\x00\x00\xcc\x01",
        1303375328,
        '2011-04-21T08:42:08Z',
    ],
    [
        "TIME17",
        "\x00\x00\x00\x00\x00\x00\xcd\x01",
        1331522826,
        '2012-03-12T03:27:06Z',
    ],
    [
        "TIME18",
        "\x00\x00\x00\x00\x00\x00\xce\x01",
        1359670324,
        '2013-01-31T22:12:04Z',
    ],
    [
        "TIME19",
        "\x00\x00\x00\x00\x00\x00\xcf\x01",
        1387817821,
        '2013-12-23T16:57:01Z',
    ],
    [
        "TIME20",
        "\x00\x53\x0d\xd4\x1e\xfd\xe9\x01",
        2147483646,
        '2038-01-19T03:14:06Z',
    ],
    [
        "TIME21",
        "\x80\xe9\xa5\xd4\x1e\xfd\xe9\x01",
        2147483647,
        '2038-01-19T03:14:07Z',
    ],
    [
        "TIME22",
        "\x00\x80\x3e\xd5\x1e\xfd\xe9\x01",
        2147483648, # 2147483648
        '(undefined)', # '2038-01-19T03:14:08Z'
    ],
    [
        "TIME23",
        "\x00\x00\x00\x00\x00\x00\x00\x02",
        2767045207, # 2767045207
        '(undefined)', # '2057-09-06T23:40:07Z'
    ],
    [
        "TIME24",
        "\x00\x00\x00\x00", # too short
        undef,
        '(undefined)',
    ],
);

foreach my $time_test (@time_tests) {
    my ($desc, $filetime, $time, $time_as_string) = @$time_test;
    my $unpacked_time1 = convert_filetime_to_epoch_time($filetime);
    my ($unpacked_time2, $len2) = unpack_windows_time($filetime);
    if (defined($time)) {
        # The test data time is a Unix epoch time
        # so is adjusted to the local OS's epoch time
        my $epoch_offset = timegm(0, 0, 0, 1, 0, 70);
        $time += $epoch_offset;
        cmp_ok($unpacked_time1, '==', $time,
            "$desc unpack_windows_time == $time");
        cmp_ok($unpacked_time2, '==', $time,
            "$desc (list) unpack_windows_time == $time");
        is($len2, 8, "$desc (list) unpack_windows_time len == 8");
    }
    else {
        ok(!defined($unpacked_time1),
            "$desc unpack_windows_time undefined");
        ok(!defined($unpacked_time2),
            "$desc (list) unpack_windows_time undefined");
    }
    is(iso8601($unpacked_time1), $time_as_string,
        "$desc iso8601 unpacked_windows_time eq '$time_as_string'");
}

# unpack_string tests
my @string_tests = (
    ["STR1", "",          '',      0], # no data
    ["STR2", "\0",        '',      1],
    ["STR3", "\0\0",      '',      1], # extra byte
    ["STR4", "abcde",     'abcde', 5], # no final null
    ["STR5", "abcde\0",   'abcde', 6],
    ["STR6", "abcde\0\0", 'abcde', 6], # extra byte
);

foreach my $string_test (@string_tests) {
    my ($desc, $data, $str, $len) = @$string_test;
    my $unpacked_str1 = unpack_string($data);
    my ($unpacked_str2, $len2) = unpack_string($data);
    if (defined($str)) {
        is($unpacked_str1, $str, "$desc unpack_string eq '$str'");
        is($unpacked_str2, $str, "$desc (list) unpack_string eq '$str'");
        is($len2, $len, "$desc (list) unpack_string len == $len");
    }
    else {
        ok(!defined($unpacked_str1),
            "$desc unpack_string undefined (invalid string)");
        ok(!defined($unpacked_str2),
            "$desc (list) unpack_string undefined (invalid string)");
    }
}

# unpack_unicode_string tests
my @unicode_tests = (
    ["UNI1",  "",                        '',       0], # no data
    ["UNI2",  "\0",                      '',       0], # missing byte
    ["UNI3",  "\0\0",                    '',       2],
    ["UNI4",  "\0\0\0",                  '',       2], # extra byte
    ["UNI5",  "\0\0\0\0",                '',       2], # two extra bytes
    ["UNI6",  "a\0b\0c\0d\0e",           'abcd',   8], # missing byte
    ["UNI7",  "a\0b\0c\0d\0e\0",         'abcde', 10], # no final null
    ["UNI8",  "a\0b\0c\0d\0e\0\0",       'abcde', 10], # missing byte
    ["UNI9",  "a\0b\0c\0d\0e\0\0\0",     'abcde', 12],
    ["UNI10", "a\0b\0c\0d\0e\0\0\0\0",   'abcde', 12], # extra byte
    ["UNI11", "a\0b\0c\0d\0e\0\0\0\0\0", 'abcde', 12], # two extra bytes
);

foreach my $unicode_test (@unicode_tests) {
    my ($desc, $data, $str, $len) = @$unicode_test;
    my $unpacked_str1 = unpack_unicode_string($data);
    my ($unpacked_str2, $len2) = unpack_unicode_string($data);
    if (defined($str)) {
        is($unpacked_str1, $str,
            "$desc unpack_unicode_string eq '$str'");
        is($unpacked_str2, $str,
            "$desc (list) unpack_unicode_string eq '$str'");
        is($len2, $len,
            "$desc (list) unpack_unicode_string len == $len");
    }
    else {
        ok(!defined($unpacked_str1),
            "$desc unpack_unicode_string undefined (invalid string)");
        ok(!defined($unpacked_str2),
            "$desc (list) unpack_unicode_string undefined (invalid string)");
    }
}

# unpack_guid tests
my @guid_tests = (
    [
        "GUID1",
        "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF",
        "{33221100-5544-7766-8899-AABBCCDDEEFF}",
    ],
    [
        "GUID2",
        "\xE0\x4F\xD0\x20\xEA\x3A\x69\x10\xA2\xD8\x08\x00\x2B\x30\x30\x9D",
        "{20D04FE0-3AEA-1069-A2D8-08002B30309D}",
    ],
    [
        "GUID3", # too short
        "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE",
        undef,
    ],
    [
        "GUID4", # extra data
        "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00",
        "{33221100-5544-7766-8899-AABBCCDDEEFF}",
    ],
);

sub check_guid {
    my ($actual_guid, $expected_guid, $desc) = @_;

    ok(defined($actual_guid), "$desc defined") or return;
    is($actual_guid->as_string, $expected_guid, "$desc as_string");
}

foreach my $guid_test (@guid_tests) {
    my ($desc, $data, $guid, $len) = @$guid_test;
    my $unpacked_guid1 = unpack_guid($data);
    my ($unpacked_guid2, $len2) = unpack_guid($data);
    if (defined($guid)) {
        check_guid($unpacked_guid1, $guid, "$desc unpack_guid");
        check_guid($unpacked_guid2, $guid, "$desc (list) unpack_guid");
        is($len2, 16, "$desc (list) unpack_guid len");
    }
    else {
        ok(!defined($unpacked_guid1),
            "$desc unpack_guid undefined (invalid guid)");
        ok(!defined($unpacked_guid2),
            "$desc (list) unpack_guid undefined (invalid guid)");
    }
}
