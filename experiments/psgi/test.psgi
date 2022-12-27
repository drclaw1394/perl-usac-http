use strict;
use warnings;
use feature ":all";

use Data::Dumper;
use Plack::Request; 

use Plack::Builder;
my $app= sub {
	my $env=shift;
	state $c=0;
  #my $req=Plack::Request->new($env);	

	[200,[],["content from psgi file"]];
};



builder {
    #enable "AccessLog";
    #enable "StackTrace";
    #enable "Auth::Basic", authenticator => \&authen_cb;
    $app;
};

sub authen_cb {
    my($username, $password, $env) = @_;
    return $username eq 'admin' && $password eq 's3cr3t';
}
