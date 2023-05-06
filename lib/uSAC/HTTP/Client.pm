package uSAC::HTTP::Client;
use feature qw<state isa>;
use Log::ger;
use Object::Pad;

use uSAC::HTTP::Header ":constants";
use uSAC::HTTP::Route;
use uSAC::HTTP::Session;
class uSAC::HTTP::Client :isa(uSAC::HTTP::Server);
no warnings "experimental";


use feature "say";


field $_host_pool_limit :param=undef;
field $_cookie_jar_path :param=undef;
field $_cv;

field $_sessions;
field $_read_size;

field $_zombies;
field $_zombie_limit;
field $_application_parser;

BUILD {
  $self->mode=1;          # Set mode to client.
  $_host_pool_limit//=5;  # limit to 5 concurrent connections by default
  $_zombies=[];

}

method stop {
	$_cv->send;
}

method run {
  #my $self=shift;
  my $sig; $sig=AE::signal(INT=>sub {
      $self->stop;
      $sig=undef;
  });

	$self->rebuild_dispatch;

  if($self->options->{show_routes}){
    Log::OK::INFO and log_info("Routes for selected hosts: ".join ", ", $self->options->{show_routes}->@*);
    $self->dump_routes;
    #return;
  }

	Log::OK::TRACE and log_trace(__PACKAGE__. " starting client...");
  $self->running_flag=1;

  #Trigger any queued requests
  for my ($k,$v)($self->host_tables->%*){
    $self->_request($v);
  }

  require AnyEvent;
	$_cv=AE::cv;
	$_cv->recv();
  say "AFTER";
}


my $session_id=0;
method request {
  Log::OK::TRACE and log_trace __PACKAGE__." request";
  # Queue a request in host pool and trigger if queue is inactive
  #
  my($host, $method, $path, $header, $payload)=@_;

  $header//={};
  $payload//="";
  $path||="/";
  state $request_id=0;

  my $options;

  # Attempt to connect to host if we have no connections  in the pool
  state $any_host=$self->host_tables->{"*.*"};

  my $entry=$self->host_tables->{$host}//$any_host;
  
  # Push to queue


  push $entry->[uSAC::HTTP::Site::REQ_QUEUE]->@*,
    [$host, $method, $path, $header, $payload, undef, $request_id++, $entry];

  # kick off queue processin if needed
  #
  $self->_request($entry) if $self->running_flag;
  $request_id;
}

# process the queue for a host table, given the session to reuse.
# If no session is provided then create a new one, up to limit
method _request {
  Log::OK::TRACE and log_trace __PACKAGE__." _request";
  die "_request must be made with a host table" unless @_ >=1 and ref $_[0] eq "ARRAY";
  # From the given host table and session attmempt to execute the request stored in $details
  # or of extract from the host queue
  # Schedules the request for the next loop of the event system
  #
  my ($table, $session)=@_;

  my $details=shift($table->[uSAC::HTTP::Site::REQ_QUEUE]->@*);

  # If a session is supplied reuse it if possible
  #
  if($session){
    $session->closeme=1;
    $session->drop;
    Log::OK::INFO and log_info "Session reuse attempted";
      $table->[uSAC::HTTP::Site::ACTIVE_COUNT]--;

      unless($details){
        # No more work to do so add the session to the idle pool
        #
        Log::OK::INFO and log_info "No futher requests to process for this host table. Return to idle pool";
        #push $table->[uSAC::HTTP::Site::IDLE_POOL]->@*, $session;
        return;
      }
      $table->[uSAC::HTTP::Site::ACTIVE_COUNT]++;
      return $self->__request($table, $session, $details) 
  }
  
  return unless $details;

  #NO session but details. request from user, not retrigger
  # parse the host and port from the table
  my $host=$details->[0];#Host;
  my ($__host, $port)=split ":", $host; 
  $port//=80;

  my $limit =10;
  if( 
    ($limit<=0 or $table->[uSAC::HTTP::Site::ACTIVE_COUNT] < $limit)  # Check limit

    ){
      $table->[uSAC::HTTP::Site::ACTIVE_COUNT]++;

      #Create another connection so long as it is doesn't exceed the limit
      $self->do_stream_connect($__host, $port, sub {
        my ($socket, $addr)=@_;
        $table->[uSAC::HTTP::Site::ADDR]=$addr;
        # Create a session here
        #
        my $scheme="http";
        Log::OK::TRACE and log_trace __PACKAGE__." CRATEING NEW SESSION";

        my $session=uSAC::HTTP::Session->new;
        $session->init($session_id, $socket, $_sessions, $_zombies, $self, $scheme, $addr, $_read_size);

        unless($_application_parser){
          require uSAC::HTTP::v1_1_Reader;
          $_application_parser=\&uSAC::HTTP::v1_1_Reader::make_parser;
        }

        say "APPLICATION PARSER: ".$_application_parser;
        $session->push_reader($_application_parser->(session=>$session, mode=>1, callback=>sub {say "DUMMY PARSER CALLBACK====="}));
        $_sessions->{ $session_id } = $session;

        $session_id++;
        $self->__request($table, $session, $details);
      },

      sub {
        # connection error
        #
        $table->[uSAC::HTTP::Site::ACTIVE_COUNT]--;
        say "error callback for stream connect: $_[1]";
        IO::FD::close $_[0]; # Close the socket
        my($route, $captures)=$table->[uSAC::HTTP::Site::HOST_TABLE_DISPATCH]($details->[1]." ".$details->[2]);

        die "No route found for $host" unless $route;

        $route->[1][ROUTE_ERROR_HEAD]->($route);
      }
    )
  }
  else{
    # Sit tight.. a connection will become available soon.. hopefully!
    Log::OK::TRACE and log_trace __PACKAGE__. " request queued but waiting for in flight to finish";
  }
}



#  Push a request to the request queue
#
method __request {

  my ($table, $session, $details)=@_;


  my $version;
  my $ex;
  #my $id;
  #my $fh;
  my $scheme;
  my $peers;
  my $i;
  
  uSAC::IO::asap {

    my $host=$details->[0];
    my $method=$details->[1];
    my $path=$details->[2];
    my $out_header=$details->[3];
    my $payload=$details->[4];
    #my $cb=$details->[5];

    say "PAYLOAD FOR REQUEST: $payload";
    # At this point there should be at least one available session in the pool for the host

    #say "Idle pool is: ".Dumper $table->[IDLE_POOL];
    #my $session=pop $table->[uSAC::HTTP::Site::IDLE_POOL]->@*;
    #$table->[uSAC::HTTP::Site::ACTIVE_COUNT]++;

    # Do a route lookup
    #
    #say Dumper $details;
    my($route, $captures)=$table->[uSAC::HTTP::Site::HOST_TABLE_DISPATCH]("$method $path");

    die "No route found for $host" unless $route;

    #  Obtain session or create new. Update with the filehandle
    my %in_header=();

    #$in_header{":method"}=$method;
    #$in_header{":path"}=$path;

    $out_header->{":method"}=$method;
    $out_header->{":path"}=$path;



    # Create the REX object
    #
    $ex=$session->exports;
    $version="HTTP/1.1"; # TODO: FIX
    my $rex=uSAC::HTTP::Rex::new("uSAC::HTTP::Rex", $session, \%in_header, $host, $version, $method, $path, $ex, $captures);


    # Set the current rex and route for the session.
    # This is needed for the parser in client mode. It makes the route known
    # ahead of time.
    $ex->[3]->$*=$rex;
    $ex->[7]->$*=$route;


    # Call the head of the outerware function
    #
    $out_header->{":status"}=-1;
    $route->[1][ROUTE_OUTER_HEAD]($route, $rex, \%in_header, $out_header, $payload, undef);
  };
}




# Like clicking the link
# Uses the current url page as referer if enabled
# Treats request as httpOnly (non script)
#
method follow_link {

}

# Typing the address or clicking a shortcut. No referer
# of current page
#
method go {

}

# As per fetch api?
#
method fetch {
  my ($uri, $options)=@_;
  $options//={};
  # parse the uri
  unless($uri isa URI){
    use URI;
    $uri=URI->new($uri);
  }

  say $uri->host;
  #set host header if not present
  $options->{headers}{HTTP_HOST()}=$uri->host unless exists $options->{headers}{HTTP_HOST()};
  $self->request(
    $uri->host_port,               #Host
    $options->{method}//"GET",     #Method
    $uri->path||"/",               #Path
    $options->{headers}//{},        #Headers
    $options->{body},                           # payload
  );

}

1;
