use strict;
use warnings;
use uSAC::HTTP;
use uSAC::HTTP::PSGI;
my $app=sub {
	my $env=shift;
	state $c=0;

	#say "App". $c++;

	return [200,[],["content"]];
};
usac_site {
	usac_route "/app1"=>usac_to_psgi keep_alive=>1, $app;
}
