use 5.006;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME            => 'Parse::Win32Registry',
    VERSION_FROM    => 'lib/Parse/Win32Registry.pm',
    PREREQ_PM       => {
        'Carp'        => 0,
        'Encode'      => 0,
        'POSIX'       => 0,
        'Test::More'  => 0,
    },
    ABSTRACT_FROM   => 'lib/Parse/Win32Registry.pm',
    AUTHOR          => 'James Macfarlane',
);
