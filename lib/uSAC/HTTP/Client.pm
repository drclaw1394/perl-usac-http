package uSAC::HTTP::Client;
use feature qw<state isa>;
use Log::ger;
use Object::Pad;

use uSAC::HTTP::Constants;
use uSAC::HTTP::Header ":constants";
use uSAC::HTTP::Code ":constants";
use uSAC::HTTP::Rex;
use uSAC::HTTP::Route;
use uSAC::HTTP::Session;
use URI;
use Error::Show;

class uSAC::HTTP::Client :isa(uSAC::HTTP::Server);
no warnings "experimental";


use feature "say";

#TODO
# cookie jar
# timeout   =>session/reader/writer
# proxy
# max redirects

field $_host_pool_limit :param=undef;
field $_cookie_jar_path :param=undef;
field $_cv;

field $_sessions;
field $_read_size;

field $_zombies;
field $_zombie_limit;
field $_application_parser;
field $_total_request_count;

field $_on_error :param=undef;
field $_on_response :param=undef;

BUILD {
  $self->mode=1;          # Set mode to client.
  $_host_pool_limit//=5;  # limit to 5 concurrent connections by default
  $_zombies=[];
}



# Innerware chain dispatcher. Triggers redirects and executes queued requests
method _inner_dispatch :override {
    Log::OK::TRACE and log_trace __PACKAGE__. " end is client ".join ", ", caller;
    sub {
      #say STDERR __PACKAGE__.": END OF CLIENT INNNERWARE CHAIN";
      if($_[CB]){
        #More data to come
        #say STDERR __PACKAGE__." CALLBACK, expecting more data from parser";
        #
      }
      else {
        #No there isn't
        #
        #say STDERR __PACKAGE__." NO CALLBACK, no more data from parser expected. Return to pool";

        #TODO: Check status code
        for($_[IN_HEADER]{":status"}){
            if($_==HTTP_OK){
              #  issue new queued request
            }
            elsif(300<=$_<400){
              #Redirect. don't deque  just yet
              say STDERR __PACKAGE__." redirect $_  location: $_[IN_HEADER]{location}";
              $self->_redirect_external(@_);
            }
            elsif(400 <= $_< 500){
              # error
            }
            else {
            }
        }
        
        # The route used is always associated with a host table. Use this table
        # and attempt get the next item in the requst queue for the host
        #
        my ($entry, $session)= ($_[ROUTE][1][ROUTE_TABLE], $_[REX][uSAC::HTTP::Rex::session_]);
        $self->_request($entry, $session);

        # User agent should already know about this response
      }

    };

}

method _error_dispatch :override {
    my $_err=uSAC::HTTP::v1_1_Reader::make_error;
    sub {

            
          say "ERROR DISPATCH";
            # The route used is always associated with a host table. Use this table
            # and attempt get the next item in the requst queue for the host
            #

          say context indent=>"  ", frames=>Devel::StackTrace->new();
          my $entry;
          my $session;
            # If no rex is present, this is connection error...
            
            unless($_[REX]){

              $entry=$_[ROUTE][1][ROUTE_TABLE];
              #$_[REX][uSAC::HTTP::Rex::session_]);
              
            }
            else {
              ($entry, $session)= ($_[ROUTE][1][ROUTE_TABLE], $_[REX][uSAC::HTTP::Rex::session_]);
            }
            $entry->[uSAC::HTTP::Site::ACTIVE_COUNT]--;
            $_total_request_count--;
            $_err->();
            $_on_error and $_on_error->();

            $self->_request($entry, $session);

            #Call back to user agent?
    }

}

method stop {
  uSAC::IO::asap {
    $_cv->send;
  }
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
}


my $session_id=0;
method request {
  Log::OK::TRACE and log_trace __PACKAGE__." request";
  # Queue a request in host pool and trigger if queue is inactive
  #
  my($host, $method, $path, $header, $payload, $important)=@_;

  $header//={};
  $payload//="";
  $path||="/";
  state $request_id=0;

  my $options;

  # Attempt to connect to host if we have no connections  in the pool
  state $any_host=$self->host_tables->{"*.*"};

  my $entry=$self->host_tables->{$host}//$any_host;
  
  # Push to queue


  #push $entry->[uSAC::HTTP::Site::REQ_QUEUE]->@*,

  my $e=[$host, $method, $path, $header, $payload, undef, $request_id++, $entry];
  $important
    ? unshift $entry->[uSAC::HTTP::Site::REQ_QUEUE]->@*, $e
    : push $entry->[uSAC::HTTP::Site::REQ_QUEUE]->@*, $e
    ;


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
      $_total_request_count--;
      $_on_response and $_on_response->();

      unless($details){
        # No more work to do so add the session to the idle pool
        #
        Log::OK::INFO and log_info "No futher requests to process for this host table. Return to idle pool";
        #push $table->[uSAC::HTTP::Site::IDLE_POOL]->@*, $session;
        return;
      }
      $table->[uSAC::HTTP::Site::ACTIVE_COUNT]++;
      $_total_request_count++;
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
      $_total_request_count++;

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

        $session->push_reader($_application_parser->(session=>$session, mode=>1, callback=>sub {say "DUMMY PARSER CALLBACK====="}));
        $_sessions->{ $session_id } = $session;

        $session_id++;
        $self->__request($table, $session, $details);
      },

      sub {
        # connection error
        #
        $table->[uSAC::HTTP::Site::ACTIVE_COUNT]--;
        $_total_request_count--;
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

    # At this point there should be at least one available session in the pool for the host


    # Do a route lookup
    #
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
    my $rex=uSAC::HTTP::Rex::new("uSAC::HTTP::Rex", $session, \%in_header, $host, $version, $method, $path, $ex, $captures, $out_header);


    # Set the current rex and route for the session.
    # This is needed for the parser in client mode. It makes the route known
    # ahead of time.
    $ex->[3]->$*=$rex;
    $ex->[7]->$*=$route;


    # Call the head of the outerware function
    #
    ##$out_header->{":status"}=-1;
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
    $uri=URI->new($uri);
  }

  #set host header if not present
  $options->{headers}{HTTP_HOST()}=$uri->host unless exists $options->{headers}{HTTP_HOST()};
  $self->request(
    $uri->host_port,               # Host
    $options->{method}//"GET",     # Method
    $uri->path||"/",               # Path
    $options->{headers}//{},       # Headers
    $options->{body},              # payload
  );
}

method get {
  my ($url, $headers, $cb)=@_;
}

method post {
  my ($url, $headers, $body)=@_;
}

# expects IN_HEADER to contain a location header
method _redirect_external {
    my $url=URI->new($_[IN_HEADER]{location});
    my $hp=($url->host_port)//$_[OUT_HEADER]{":authority"};
    $self->request($hp, $_[OUT_HEADER]{":method"}, $url->path, {}, "", 1);
}

1;
