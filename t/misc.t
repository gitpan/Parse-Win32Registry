use strict;
use warnings;

use Test::More 'no_plan';

use Parse::Win32Registry qw(convert_filetime_to_epoch_time iso8601 hexdump);
use Time::Local qw(timegm);

die 'Incorrect version' if $Parse::Win32Registry::VERSION != '0.30';

my @tests = (
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

foreach my $test (@tests) {
    my ($packed_filetime, $time, $time_as_string) = @$test;
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
    is(iso8601($decoded_time), $time_as_string, "$filetime_in_hex - and iso8601 eq '$time_as_string'");
}

is(hexdump(), '', 'no hexdump');
is(hexdump(''), '', 'empty hexdump');
is(hexdump(undef), '', 'undef hexdump');
is(hexdump('www.perl.com'), <<EOT, 'small hexdump');
       0  77 77 77 2e  70 65 72 6c  2e 63 6f 6d               www.perl.com
EOT

my $text = <<EOT;
THIS PACKAGE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION,
THE IMPLIED WARRANTIES OF MERCHANTIBILITY AND FITNESS
FOR A PARTICULAR PURPOSE.
EOT
my $hexdump = <<EOT;
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
is(hexdump($text), $hexdump, 'large hexdump');
