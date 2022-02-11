package Plack::Handler::uSAC::HTTP::Server;
use strict;
use warnings;
use feature qw<say refaliasing>;

use uSAC::HTTP;
use uSAC::HTTP::PSGI;
use Data::Dumper;

sub new {
	my ($class, %options)=@_;
	bless \%options, $class;
}

sub run{
	my ($self, $app)=@_;
	#create a new server with a single endpoint added
	say Dumper $self;	
	my $server; $server=usac_server{
		usac_route ".*"=>  usac_to_psgi $app;
		usac_listen $self->{listen};
	};
	$server->run;
	$self
}

################################
# sub register_server {        #
#         my ($self, $app)=@_; #
#                              #
# }                            #
################################
1;
