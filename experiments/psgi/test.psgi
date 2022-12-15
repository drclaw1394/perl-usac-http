use strict;
use warnings;
use feature ":all";

use Data::Dumper;
use Plack::Request; sub {
	my $env=shift;
	state $c=0;
	my $req=Plack::Request->new($env);	
	#say Dumper $req->parameters;
	#say Dumper $env;
	#
	#

	[200,[],["content from psgi file"]];
};
