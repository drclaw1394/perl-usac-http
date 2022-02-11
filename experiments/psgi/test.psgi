use strict;
use warnings;
use feature ":all";

my $app=sub {
	my $env=shift;
	state $c=0;

	#say "App". $c++;

	say "IN PSGI APP";
	return [200,[],["content from psgi file"]];
};
