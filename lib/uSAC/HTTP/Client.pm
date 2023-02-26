# Middleware needs a configuration switch for client or server mode.
# in server mode, normal response codes are used for processing
# in client mode, while the codes might be used for easy of operation
# they don't get serialized
# GET /url HTTP/1.1
# Host: ...
# Accept: ...
#
package uSAC::HTTP::Client;
use strict;
use warnings;
use feature "refaliasing";
use feature "say";
use Object::Pad;
class uSAC::HTTP::Client;

# active_count_   number of active workers
# req_queue_      queue of requests to process
# addr_           pre resolved address of client
# process_cb_     what to call when done
#
use enum ("idle_pool_=0",
  qw< active_count_ req_queue_ addr_ process_cb_>
);

use AnyEvent;

use uSAC::HTTP::Code ":constants";
use uSAC::HTTP::Header ":constants";
use uSAC::HTTP::Session;
#use uSAC::HTTP::v1_1;
use uSAC::HTTP::v1_1_Reader;
use uSAC::HTTP::Rex;
use uSAC::MIME;
use uSAC::IO;
use Socket qw<AF_INET SOCK_STREAM>;

field %_host_table;   # Main data structure
                      # each entry contains a host info an a pool of sessions
field @_zombie_pool;

field $_connect_cb;

field $_default_host; #The host to use for relative  requests

field $_cv;
method do_stream_connect {
  my ($host, $port, $on_connect, $on_error)=@_;
  # Inititiate connection to server. This makes a new connection and adds to the pool

  # DNS resolution
  my $entry; 
  my $_on_connect=sub {
    my ($socket, $addr)=@_;
    $entry->[addr_]=$addr;
    push $entry->[idle_pool_]->@*, $socket;
    &$on_connect;
  };

  my $_on_error=sub {
      # tell someone about it
      &$on_error;
  };

  my $id;
  my $socket;
  if( $entry=$_host_table{$host} and $entry->[addr_]){

    # Don't do a name resolve as we already have it.
    # 
    #Create the socket 

    $socket=uSAC::IO->socket(AF_INET, SOCK_STREAM, 0);
    die "$!" unless defined $socket;
    $id=uSAC::IO->connect_addr($socket, $entry->[addr_], $_on_connect, $_on_error);
    
  }
  else {
    $id=uSAC::IO->connect($socket, $host, $port, $on_connect, $on_error);
  }
  $id;
}

# Run the user agent. Requests are pulled from the queue and processed by a
# pool of connections
method run {
  #my $self=shift;
  my $sig; $sig=AE::signal(INT=>sub {
          $self->stop;
          $sig=undef;
  });


  #Trigger async start
  my $t; $t=AE::timer 0, 0, sub {
    $self->process_queue;
    $t=undef;
  };

  require AnyEvent;
	$_cv=AE::cv;
	$_cv->recv();
}

method process_queue {
    #A requst is send via pipe to worker?
}

# request is analog to  add_route?
method request {
  no warnings "experimental";
  my ($method, $uri_opts, @middlware)=@_;
  

  #\my %options=$options;

  # TODO: Parse the uri
  my $host;#=$options{host};
  my $port;#=$options{port};

  my $options={};
  # Locate host entry
  my $entry=$_host_table{"$host:$port"};
    
  unless($entry){
    # If no entry for the host, we need to connect, and recall this 
    $self->do_stream_connect($host, $port, sub { 
        push $entry->[req_queue_]->@*, [$uri, $options];
        #trigger the que processing if requried
        $self->process_queue if($entry->[active_count_]==0);

    }, sub {
    say "error callback for stream connect";
  });
    
  }
  else {

      # host exists in our table. Add to the queue
      #
      push $entry->[req_queue_]->@*, [$uri, $options];
      $self->process_queue if($entry->[active_count_]==0);
  }
}

sub  start{
  # starts processing the queued requests


}

sub pause {
  # pause processing of queue
  
}

# Request DSL examples
#
#usac_agent{
#   usac_host  "somehost:port"; 
#   usac_middleware "List of common middleware";
#
#   usac_request "Method"=>"url"=>[sub {
#     #innerware - what to do with input/result
#   },
#   sub {
#     # Outerware - here we generate any body content, upload files/etc
#     # Payload could also be a path,
#   }],
# 
#   middleware,
#   middleware;
#   usac_run;   #Process cli arguments and enter event loop
#}



1;
