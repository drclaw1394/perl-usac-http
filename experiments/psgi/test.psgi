use strict;
use warnings;
use feature ":all";

my $app= sub {
	my $env=shift;
	state $c=0;
	[200,["test"=>"AD"],["content from psgi file"]];
};
