use strict;
use warnings;

use blib;

use Test::More tests => 2;

BEGIN { use_ok('Parse::Win32Registry') };

is($Parse::Win32Registry::VERSION, '0.22', "correct version");
