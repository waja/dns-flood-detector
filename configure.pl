#!/usr/bin/perl

use strict;

my $os = shift;

# get target listings
opendir(MAKE_TARGETS,'./makefiles');
my @targets = grep { /Makefile/ && -f './makefiles/'.$_ && s/^Makefile-// } readdir(MAKE_TARGETS);
closedir(MAKE_TARGETS);

# display usage
unless ($os && grep{/$os/}@targets) {print<<EOF;exit(0)}
usage: $0 {@targets}
EOF

# link appropriate target
symlink './makefiles/Makefile-'.$os, 'Makefile';
print "type make.\n";
