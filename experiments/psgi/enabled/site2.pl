use strict;
use warnings;
use uSAC::HTTP;
use uSAC::HTTP::PSGI;
my $app2=sub {
	my $env=shift;
	#say "App2";
	my $path=usac_path(root=>usac_dirname."/..", "test.txt");
	my $res=open my $fh, "<", $path;
	say $! unless $res;
	return [200, [], $fh];
};
usac_site{
	usac_route "/app2"=>usac_to_psgi $app2;
}
