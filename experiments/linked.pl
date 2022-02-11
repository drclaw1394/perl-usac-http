use feature ":all";
use warnings;
use strict;

use Cwd qw<abs_path>;
sub {
	my ($pack, $file, $line)=caller;
	say "File: $file";
	say "ABS: ",abs_path $file;

}->();
