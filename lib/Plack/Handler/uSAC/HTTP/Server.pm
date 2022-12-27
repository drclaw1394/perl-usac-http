package Plack::Handler::uSAC::HTTP::Server;
use strict;
use warnings;
use feature qw<say refaliasing>;

use Log::OK {
  lvl=>"trace",
  opt=>"v"
};

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
  say "adding plack route";
  $server->add_route(undef, psgi $app);
  $server->add_listeners($_) for $self->{listen}->@*;
  $server->add_listeners(":$self->{port}") if $self->{port};
  $server->workers=$self->{workers} if $self->{workers};
	$server->run;
	$self
}

1;
