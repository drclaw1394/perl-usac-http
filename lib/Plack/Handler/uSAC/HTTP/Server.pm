package Plack::Handler::uSAC::HTTP::Server;
use v5.36;
use feature qw<refaliasing try>;
no warnings "experimental";
use uSAC::Log;




sub new {
	my ($class, %options)=@_;

	bless \%options, $class;
}

# Run...
#
# Loads the usac runloop 
sub run{
  my ($self, $app)=@_;

  my $backend=$self->{backend};
  $backend//="AnyEvent"; 

  my $level=$self->{verbose}//"info";
  die $@ unless eval "
  use Log::OK {
    lvl=>\"$level\",
  };
  use $backend;

  use uSAC::IO;
  use uSAC::Main;

  use uSAC::HTTP::Server;
  use uSAC::HTTP::Middleware::PSGI;
  1;
  ";

  uSAC::Main::_main( sub{

    #
    # This tricky bit of code is needed to allow the log level from Log::OK to be
    # set from the command line. Normally this is handled automatically, but plackup 
    # consumes the command line options and spits them back out as a hash (self).
    #

    my $server=uSAC::HTTP::Server->new;
    $server->process_cli_options([$self->%*]);

    # 
    # Set the default route in the default 'host table' to the PSGI application
    #
    #sleep 1;
    $server->add_route(undef, uSAC::HTTP::Middleware::PSGI::uhm_psgi($app));


    #
    # Setup one or more listeners from  a --listen argument
    #
    $server->add_listeners("$_,t=stream") for $self->{listen}->@*;


    # Create a listener form the --port and --host options, only if
    # --listen is not specified. This required for loading via loader
    # NOTE IPv6 support is busteed 

    #########################################################
    # unless($self->{listen}->@*){                          #
    #                                                       #
    #   my $port=$self->{port};#//5000; #default port       #
    #   my $host=$self->{host};                             #
    #   if(defined($host) and defined($port)){              #
    #     my $t="";                                         #
    #     $t.="a=$host," if $host;                          #
    #     $server->add_listeners("a=$t,po=$port,t=stream"); #
    #   }                                                   #
    #                                                       #
    # }                                                     #
    #########################################################


    #
    # Configure the number of worker child processes to execute
    #
    $server->workers=$self->{workers}//$self->{max_workers} if defined($self->{workers}) or defined($self->{max_workers});

    # 
    # RUN IT!
    #
    #
    try {
     $server->run;
    }
    catch($e){
      Log::OK::ERROR and log_error $e;
      exit -1;
    }


    $self
  });
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

