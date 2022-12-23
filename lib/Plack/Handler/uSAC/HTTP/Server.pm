package Plack::Handler::uSAC::HTTP::Server;
use strict;
use warnings;
use feature qw<say refaliasing>;

use uSAC::HTTP;
use uSAC::HTTP::Middleware::PSGI;

sub new {
	my ($class, %options)=@_;
	bless \%options, $class;
}

sub run{
	my ($self, $app)=@_;

	#create a new server with a single endpoint added
	my $server=uSAC::HTTP::Server->new;
  $server->add_route(qr|.*|, usac_to_psgi $app);
  $server->add_listeners($_) for $self->{listen}->@*;
  $server->add_listeners(":$self->{port}");
  $server->workers=$self->{workers};
	$server->run;
	$self
}

1;
