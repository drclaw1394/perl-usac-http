package Plack::Handler::uSAC::HTTP::Server;
use strict;
use warnings;
use feature qw<say refaliasing>;
use Log::ger;
use Log::ger::Output "Screen";

#use uSAC::HTTP;
#use uSAC::HTTP::Server;

#use Log::ger;


sub new {
	my ($class, %options)=@_;
	bless \%options, $class;
}

sub run{
	my ($self, $app)=@_;

  #
  # This tricky bit of code is needed to allow the log level from Log::OK to be
  # set from the command line. Normally this is handled automatically, but plackup 
  # consumes the command line options and spits them back out as a hash (self).
  #
  my $level=$self->{verbose}//"info";
  die $@ unless eval "
  use Log::OK {
    lvl=>\"$level\",
  };
  use uSAC::HTTP::Server;
  use uSAC::HTTP::Middleware::PSGI;
  1;
  ";

  use Data::Dumper;
  say Dumper $self;

	my $server=uSAC::HTTP::Server->new;

  # 
  # Set the default route in the default 'host table' to the PSGI application
  #
  $server->add_route(undef, uSAC::HTTP::Middleware::PSGI::psgi($app));


  #
  # Setup one or more listeners from  a --listen argument
  # Ignore the --port and --host options as this is combined
  # into listen and the IPv6 support is broken.
  #
  $server->add_listeners($_) for $self->{listen}->@*;


  #
  # Configure the number of worker child processes to execute
  #
  $server->workers=$self->{workers}//$self->{max_workers} if defined($self->{workers}) or defined($self->{max_workers});

  # 
  # RUN IT!
  #
	$server->run;


	$self
}

1;

__END__
=head1  NAME

Plack::Handler::uSAC::HTTP::Server - Plack handler for uSAC HTTP Server

=head1 SYNOPSIS

  plackup -s uSAC::HTTP::Server [options] app_path.psgi

=head1 DESCRIPTION

Implements the Plack Handler sub class for to allow C<uSAC::HTTP::Server>  to
be run from L<plackup>.


=head2 Supported plackup Pass Through Options

=head3 --listen

Accepts "host:port" strings with literal IPv4 and IPv6 addresses. Examples include:

  0.0.0.0:8080    #Listen on all IPv4 interfaces on port 8080
  [::]:8080       #Listen on all IPv6 and IPv4 interfaces on port 8080
  :8080           #Same as above
  0.0.0.0         #Listen on all IPv4 interfaces on default port 5000


=head3 --host and --port (via --listen)

When using a --host or --port switch, plackup combines them into an equivilant
--listen option. At the time of writing it handles literal IPv6 address poorly,
so this handler B<only> looks at the --listen switch, B<not> --host and --port
directly

  
=head2 Addtional Options

=head3 --workers --max-workers

Sets the number of worker processes:

=over


=item undef or <0

automatic worker  calculation.

=item 0

No workers. Manager procress does it all

=item >0

Explicit worker count

=back


=head3 --disable_workers

Same as --workers -1

Forces single process mode

=head2 --verbose

Sets the logging level of the server internals. Levels are based on C<Log::OK>
and with C<Log::ger>

  eg
  --verbose info
  --verbose trace

=head1 LOGGING

In order to get the server logging (not Plack logging middleware) running
through plackup, don't use any C<uSAC::HTTP> modules in your psgi application.
Normally you wouldn't but, now you know not to.

The default logging level is set to info.


=head1 TODO

Eventually the event loop backend will be selectable

