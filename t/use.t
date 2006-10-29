use strict;
use warnings;

use Test::More tests => 2;

BEGIN { use_ok('Parse::Win32Registry') };

is($Parse::Win32Registry::VERSION, '0.24', "correct version");
