use v5.36;
package uSAC::HTTP::Server; 
our $VERSION = 'v0.1.0';
use feature "try";

# Attempt event system detection here...
# and load default if none found
#

use Object::Pad;          # Class
use Log::ger;             # Log system
use Log::OK { lvl=>"info" };  # CLI control of log system

# Socket::More also exports Socket Symbols
use Socket::More;         # Socket symbols and passive socket


use IO::FD;               # IO
use uSAC::IO;             # Readers/writers
use uSAC::IO::Acceptor;   # Acceptors

use uSAC::HTTP;           # uSAC::HTTP Core code
use uSAC::HTTP::Session;  # 'session' stuff
use uSAC::Util;           # Auxillary functions

use Hustle::Table;		    # Fancy dispatching of endpoints



use feature qw<refaliasing say state current_sub>;
use constant::more NAME=>"uSAC", VERSION=>"v0.1.0";

no warnings "experimental";


use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK);





# Use the common tag to rexport common middleware
use Export::These ":common";



my $session_id=0;


#
# This is used as the default entry in a Hustle::Table and acts as a marker to
# allow setup code to force the actual default handler below. It is needed to
# allow an default matcher to be set from outside the server/site.
#
my $dummy_default=[];

#
# If nothing else on this server matches, this will run
# And if that happens it it most likley a protocol error
# ie expecting a request line but getting something else
#
sub _default_handler {
    require uSAC::HTTP::Middleware::Log;
(
    uSAC::HTTP::Middleware::Log::uhm_log(),
    sub {
			Log::OK::DEBUG and log_debug __PACKAGE__. " DEFAULT HANDLER"; 
			Log::OK::DEBUG and log_debug __PACKAGE__.join ", ", $_[IN_HEADER]->%*;
			$_[PAYLOAD]="NOT FOUND";
			return &rex_error_not_found;
      undef;
		}
  )
}

sub _reexport {
  my ($pack, $target)=(shift, shift);

  # Re export to the caller package
  #
  $_->import for (qw<uSAC::HTTP uSAC::HTTP::Site uSAC::Util>);


  # Preload common middleware  if asked
  #
  if(grep /:common/, @_){
    for(<uSAC::HTTP::Middleware::{Trace,Static,Slurp,Redirect,Log,TemplatePlex}>){
      { local $Exporter::ExportLevel=0; need $_; }
      $_->import;
    }
  }

}


class uSAC::HTTP::Server :isa(uSAC::HTTP::Site);

no warnings "experimental";
field $_host_tables :mutator;
field $_cb;
field $_listen :param=["po=5001,addr=::"];
field $_listen_spec;
field $_graceful;
field $_aws;
field $_aws2;
field $_fhs2;
field $_fhs3;
field $_backlog;
field $_read_size :mutator :param=4096;
field $_sessions;
field $_active_connections;
field $_total_connections;
field $_active_requests;
field $_zombies;
field $_zombie_limit;
field $_stream_timer;
field $_server_clock;
field $_mime;
field $_sub_product :param="ductapeXchansaw";
field $_workers :mutator :param=0;
field $_cv;
field $_options :reader;
field $_application_parser :param=undef;
field $_total_requests;
field $_static_headers :mutator;



BUILD {
  
  # server is top level, set  default mime
	$self->set_mime_db(uSAC::MIME->new); # set  and index
	$self->set_mime_default("application/octet-stream");

  $self->prefix="/";
  $self->id="/";
	$_host_tables={};
  $_zombies=[];
	$_zombie_limit//=100;
	$_static_headers={};#STATIC_HEADERS;

  $self->mode//=0; #Only set to server mode if it hasn't been defined.

  # Add the wildcard host, incase no sites or route are added. Gives at least
  # one table with rebuilding the routes/dispatch
  # 
  $_host_tables->{"*.*"}=[
    Hustle::Table->new($dummy_default), # Table
    {},                                  # Table cache
    undef,                              #  dispatcher
    "",
    [],
    [],
    0

  ];

	$_backlog=4096;
	$_read_size=4096;
  $_options={};

	$_sessions={};

  $self->_add_listeners(ref($_listen) eq "ARRAY"?@$_listen:$_listen);

	$self->static_headers={
	  HTTP_SERVER()=>(uSAC::HTTP::Server::NAME."/".uSAC::HTTP::Server::VERSION." ".join(" ", $_sub_product) )};
}

method _setup_dgram_passive {
	my ($l)=@_;
	#Create a socket from results from interface
	IO::FD::socket my $fh, $l->{family}, $l->{type}, $l->{protocol} or die "listen/socket: $!";

	IO::FD::setsockopt($fh, SOL_SOCKET, SO_REUSEADDR, pack "i", 1);
	
	if($l->{family}== AF_UNIX){
		unlink $l->{path};
	}
	else{
		IO::FD::setsockopt $fh, SOL_SOCKET, SO_REUSEPORT, pack "i", 1;

	}

	defined(IO::FD::bind $fh, $l->{addr})
		or die "listen/bind: $!";

	if($l->{family}== AF_UNIX){
		chmod oct('0777'), $l->{path}
			or warn "chmod $l->{path} failed: $!";
	}
	else {

	}

	IO::FD::fcntl $fh, F_SETFL,O_NONBLOCK;
	$_fhs3->{$fh} = $fh;
}


method _setup_stream_passive {
	my ($l)=@_;

	#Create a socket from results from interface
	defined IO::FD::socket my $fh, $l->{family}, $l->{type}, $l->{protocol} or die "listen/socket: $!";

	IO::FD::setsockopt($fh, SOL_SOCKET, SO_REUSEADDR, pack "i", 1);
	
	if($l->{family}== AF_UNIX){
		unlink $l->{path};
	}
	else{
		IO::FD::setsockopt $fh, SOL_SOCKET, SO_REUSEPORT, pack "i", 1;
	}


	defined(IO::FD::bind $fh, $l->{addr})
		or die "listen/bind: $!";
	#Log::OK::INFO and log_info("Stream bind ok");
	
	if($l->{family} == AF_UNIX){
		chmod oct('0777'), $l->{path}
			or warn "chmod $l->{path} failed: $!";
	}
	else {
		IO::FD::setsockopt $fh, IPPROTO_TCP, TCP_NODELAY, pack "i", 1;
	}

	my $flags=IO::FD::fcntl $fh, F_GETFL, 0;
	$flags|=O_NONBLOCK;

	defined IO::FD::fcntl $fh, F_SETFL, $flags or die "COULD NOT SET NON BLOCK on $fh: $!";

	$_fhs2->{$fh} = $fh;


	#Finally run the listener
	for ( values  %$_fhs2 ) {
		IO::FD::listen $_, $_backlog
			or die "listen/listen on ".( $_).": $!";
	}
}


#Filter the interface listeners to the right place
method do_passive {
  #my $self = shift;
	#Listeners are in interface format
	die "No listeners could be found" unless @$_listen_spec;
	for my $l (@$_listen_spec){
		#Need to associate user protocol handler to listener type... how?
		if($l->{type}==SOCK_STREAM){
			$self->_setup_stream_passive($l);
		}
		elsif($l->{type}==SOCK_DGRAM){
			$self->_setup_dgram_passive($l);
		}
		else {
			die "Unsupported socket type";
		}
	}

}





# 
# Each worker calls this after spawning. Sets up timers, signal handlers etc
#
method prepare {
	#setup timer for constructing date header once a second
  #my ($self)=shift;

  #Start the acceptors running on this worker 
  $_->start for(values $_aws->%*);
  
  #Setup the watchdog timer for the any active connections
	my $interval=1;
	my $timeout=20;
	$_server_clock=time;	

	#Timeout timer
	#
  #$SIG{ALRM}=
  #$_stream_timer=AE::timer 0, $interval,
  $_stream_timer=uSAC::IO::timer 0, $interval,
  
    sub {
      #iterate through all connections and check the difference between the last update
      $_server_clock+=$interval;
      #and the current tick
      my $session;
      for(keys $_sessions->%*){
        $session=$_sessions->{$_};

        if(($_server_clock-$session->time)> $timeout){
          Log::OK::DEBUG and log_debug "DROPPING ID: $_";
          $session->closeme=1;
          $session->drop;
        }
      }
      
      #alarm	 $interval;# if $self->[sessions_]->%*; #only start interval if something to watch?
    };
  
  #alarm $interval;
  Log::OK::INFO and log_info "Accepting connections on PID: $$";
}






#
# Iterate over passive sockets and setup an asyncrhonous acceptor
# 
method do_accept{
  #Accept is only for SOCK_STREAM 
  Log::OK::DEBUG and log_debug __PACKAGE__. " Accepting connections";

  my $do_client=$self->make_stream_accept;

  my @peers;
  my @afh;
  for my $fl ( values %$_fhs2 ) {
    #
    # Create an acceptor here but we start it later
    #
    #
    $_aws->{ $fl } =my $acceptor=uSAC::IO::Acceptor->create(fh=>$fl, on_accept=>$do_client, on_error=>sub {});
  }
  Log::OK::TRACE and log_trace "Setup of stream passive socket complete";
}



sub make_do_dgram_client {
	#A single dgram listener is all thats required. it needs to call.
	#todo
}

#
#Returns a sub for processing new TCP client connections
#
method make_stream_accept {
  \my @zombies=$_zombies;
  \my %sessions=$_sessions;


  # TLS extensions...
  # Server name indication...
  #
  #

  # Application Layer Protocol Negotiation
  #

  my $session;
  unless($_application_parser){
    need uSAC::HTTP::v1_1_Reader;
    $_application_parser=\&uSAC::HTTP::v1_1_Reader::make_parser;
  }

  
  my $parser=$_application_parser; 

  sub {
    my ($fhs, $peers)=@_;
    my $i=0;
    for my $fh(@$fhs){
      # TCP_NODELY etc here?
      #
      my $scheme="http";

      Log::OK::DEBUG and log_debug "Server new client connection: id $session_id";

      if(@zombies){
        $session=pop @zombies;
        $session->revive($session_id, $fh, $scheme, $peers->[$i]);
      }
      else {
        $session=uSAC::HTTP::Session->new;
        $session->init($session_id, $fh, $_sessions, $_zombies, $self, $scheme, $peers->[$i],$_read_size);
        $session->push_reader($parser->(session=>$session, mode=>0, callback=>$self->current_cb));
      }

      $i++;
      $sessions{ $session_id } = $session;

      $session_id++;
    }

    @{$fhs}=();
    @{$peers}=();
  }
}




method current_cb {
  $_cb;
}


#
# This is how the server is told to add a route to a host. Not really for
# direct access. use the add_route method on a site instead
#
method add_host_end_point{
	my ( $host, $matcher, $ctx, $type)=@_;

	#ctx is route context array [$site, $endpoint, $outer, $default_flag]
  #
	#This becomes the value field in hustle table entry
	#[matcher, value, type, default]
  
	my $table=$_host_tables->{$host};
  unless ($table){
    # Host table does not exist. So create on. Add a default path also
    $_host_tables->{$host}=$table=[
      Hustle::Table->new($dummy_default), # Table
      {},                                  # Table cache
      undef,                              #  dispatcher
      "",
      [],
      [],
      0

    ];
  }


  # NOTE: This is the route context. This is  a back refernce to the table
  # TODO: Possibly weaken this
  $ctx->[ROUTE_TABLE]=$table;

  #Actually add the entry to hustle table
	$table->[0]->add(matcher=>$matcher, value=>$ctx, type=>$type);
}

method rebuild_routes {
  # Add the staged routes for site structure into server
  $self->SUPER::rebuild_routes;
  

  # Create a special default site for each host that matches any method and uri
  #  An entry is only added if the dummy_defualt is currently the default
  #
  for my $host (keys $_host_tables->%*) {
    Log::OK::TRACE and log_trace(__PACKAGE__. " $host");
    #If the table has a dummy catch all then lets make an fallback
    my $entry=$_host_tables->{$host}; 
    my $last=$entry->[0]->@*-1; #Index of default in hustle table

    if($entry->[0][$last][1] == $dummy_default){
      Log::OK::DEBUG and log_debug "Adding default handler to $host";
      my $site=uSAC::HTTP::Site->new(id=>"_default_$host", host=>$host, server=>$self, mode=>$self->mode);
      $site->parent_site=$self;
      $site->_add_route([$Any_Method], undef, _default_handler);
    }
  }
}

method rebuild_dispatch {

  Log::OK::DEBUG and log_debug(__PACKAGE__. " rebuilding dispatch...");
  #Install error routes per site
  #Error routes are added after other routes.



  # Show a warning (if enabled) if the there is exactly the same number of
  # routes as hosts. This means that all host tables will only fail matching to
  # either defaults at all times

  if($self->routes == keys $_host_tables->%*){
    Log::OK::WARN and log_warn "Multiple host tables, but each only contain default route matching";
    #exit;
  }


    # prepare dispatcher 
    for(values $_host_tables->%*){
      Log::OK::TRACE and log_trace __PACKAGE__." processing table entry for rebuild";
      $_->[uSAC::HTTP::Site::HOST_TABLE_DISPATCH]=$_->[uSAC::HTTP::Site::HOST_TABLE]->prepare_dispatcher(cache=>$_->[uSAC::HTTP::Site::HOST_TABLE_CACHE]);
      #say join ", ", @$_;
    } 


    # Pre lookup the any host
    #my $any_host=$lookup{"*.*"};
    my $any_host=$_host_tables->{"*.*"};


    # If we only have single host table, it is the anyhost. It it only has one
    # route it is the default. So we are in single end point mode. no need to
    # perform any routing lookups as we already know which one to use
    #
    my $single_end_point_mode=(
      ($self->routes == keys $_host_tables->%*)
        and (keys $_host_tables->%*)==1);


    if($single_end_point_mode){

      (my $route, my $captures)=$any_host->[uSAC::HTTP::Site::HOST_TABLE_DISPATCH]("");
      $_cb=sub {
        #Always return the default out of the any_host table
        $route->[1][ROUTE_COUNTER]++;	
        ($route, $captures);
      };
      Log::OK::WARN and log_warn "Single end point enabled";
      return;
    }



    #
    # Parser calls the following to identify / match a route for header and path
    # information. The route contains the middlewares prelinked to process the
    # requests
    #
  my $table;
  $_cb=sub {
    use Time::HiRes qw<time>;
    Log::OK::TRACE and  log_trace "IN SERVER CB: @_";

    Log::OK::TRACE and  log_trace join ", ", values $_host_tables->%*;
    #my ($host, $input);
    
    # input is "method url"
    
    #$table=$lookup{$_[0]//""}//$any_host;
    $table=$_host_tables->{$_[0]//""}//$any_host;

    #Log::OK::TRACE and  log_trace  join ", ",$table->@*;
    (my $route, my $captures)= $table->[uSAC::HTTP::Site::HOST_TABLE_DISPATCH]($_[1]);

    #Hustle table entry structure:
    #[matcher, value, type default]
    #
    #ctx/value is  a 'route' structure:
    #[site, linked_innerware, linked_outerware, counter]
    #  0 ,		1 	,	            2		,           3

    Log::OK::DEBUG and log_debug __PACKAGE__." ROUTE: ".join " ,",$route;
    Log::OK::DEBUG and log_debug __PACKAGE__." ROUTE: ".join " ,",$route->@*;

    #
    # Increment the counter on the route
    #
    $route->[1][ROUTE_COUNTER]++;	


    # TODO: Better Routing Cache management.
    # if the is_default flag is set, this is an unkown match.
    # so do not cache it

    delete $table->[uSAC::HTTP::Site::HOST_TABLE_CACHE]{$_[1]} if $route->[3];
    #return the entry sub for body forwarding
    Log::OK::TRACE and log_trace "END OF SERVER CB";
    ($route, $captures);
  };
}


method stop {
  uSAC::IO::asap(sub {
    $_cv->send;
  });
}

method run {
  #my $self=shift;
  my $sig; $sig=AE::signal(INT=>sub {
          $self->stop;
          $sig=undef;
  });

  $self->rebuild_routes;
	$self->rebuild_dispatch;

  

  if($_options->{show_routes}){
    Log::OK::INFO and log_info("Routes for selected hosts: ".join ", ", $_options->{show_routes}->@*);
    $self->dump_routes;
    #return;
  }
	Log::OK::TRACE and log_trace(__PACKAGE__. " starting server...");
  
	$self->do_passive;
	$self->do_accept;

	$self->dump_listeners;
  
  #TODO: Preforking server
  #Seems like there are no 'thundering herds' in linux and darwin
  #Calles to accept are serialised. Use SO_REUSEPORT for 'zero' downtime
  #server reloads

  if(not defined($_workers) or $_workers<0){
    #Attempt to auto pick the number of workers based on cpu information
    try {
      require Sys::Info;
      my $info=Sys::Info->new;
      $_workers=$info->device("cpu")->count;
      Log::OK::WARN and log_warn "Attempting to guess a nice worker count...";

    }
    catch($e){
      $_workers=0;
      Log::OK::WARN and log_warn "Error guessing worker count. Running in single process mode (workers =0)";
    }
  }
  if($_workers){
    Log::OK::INFO and log_info "Running $_workers workers + manager";
  }
  else {
    Log::OK::INFO and log_info "Running single process mode";
  }

  if($_workers){
    for(1..$_workers){
      my $pid=fork;
      if($pid){
        #server
      }
      else {
        #child, start accepting only on workers
        $self->prepare;
        last;
      }
    }
  }
  else {
        $self->prepare;
  }

  require AnyEvent;
	$_cv=AE::cv;
	$_cv->recv();
  $self;
}


method dump_listeners {
	#Generate a table of all the listeners
	
  #my ($self)=@_;
	try {
		require Text::Table;
		my $tab=Text::Table->new("Interface", "Address", "Family", "Group", "Port", "Path", "Type");
			$tab->load([
				$_->{interface},
				$_->{address},
				family_to_string($_->{family}),
				$_->{group},
				$_->{port},
				$_->{path},
				sock_to_string($_->{type}),

				])
			for @$_listen_spec;
			#$tab->load(@data);
		Log::OK::INFO and log_info join "", $tab->table;

	}
	catch($e){
		Log::OK::ERROR and log_error "Could not load Text::Table for listener dumping";
	}
}

method routes {
  #my $self=shift;
  my @routes;
  for my $host (sort keys $_host_tables->%*){
    my $table= $_host_tables->{$host};
    for my $entry ($table->[0]->@*){
      push @routes, $entry;
    }
  }
  @routes;
}

method dump_routes {
  #my ($self)=@_;
  use re qw(is_regexp regexp_pattern);
  try {
    require Text::Table;
    for my $host (sort keys $_host_tables->%*){
      my $table= $_host_tables->{$host};
      my $tab=Text::Table->new("Match", "Match Type", "Site ID", "Prefix", "Host");
      #
      # table is hustle table and cache entry
      # 

      # Only dump the host routes if the route spec
      last unless $_options->{show_routes};
      next unless grep $host=~ $_, $_options->{show_routes}->@*;

      
      for my $entry ($table->[0]->@*){
        
        my $site=$entry->[1][ROUTE_SITE];


        my $matcher=$entry->[0];
        if(is_regexp $matcher){
          $matcher=regexp_pattern $matcher;
          while($matcher=~s|\(\?\^u\:(.*)\)|$1|){};

        }
        my $key;
        my @a;

        if($site){
          $tab->load([$matcher, $entry->[2]//"regexp", $site->id, $site->prefix, join "\n",$host]);
        }
        else{
          $tab->load([$matcher, $entry->[2]//"regexp", "na", "na", join "\n",$host]);
        }
      }
      Log::OK::INFO and log_info join "", $tab->table;

    }
  }
  catch($e){
		Log::OK::ERROR and log_error "Could not load Text::Table for route listing";

  }
  

	#Make seperate tables by site?
	#sort by group by method

}



method _add_listeners {
  #my $site=shift;
  for my $spec(@_){
    #my %options=@_;

    my @spec;
    my @addresses;

    my $ref=ref $spec;
    if($ref  and $ref ne "HASH"){
      die "Listener must be a HASH ref or a sockaddr_passive cli string";

    }
    elsif($ref eq ""){
      @spec=parse_passive_spec($spec);
      #use feature ":all";
      die "could not parse listener specification" unless $spec;
    }
    else {
      #Hash
      @spec=($spec);
    }

    @addresses=sockaddr_passive(@spec);
    push @$_listen_spec, @addresses;
  }
  #say Dumper $_listen_spec;
  $self;
}

method listeners:lvalue {
  $_listen_spec;
}



method application_parser :lvalue {
  $_application_parser;
    
}

method process_cli_options{
  my $options=@_?[@_]:\@ARGV;


  #Attempt to parse the CLI options
  require Getopt::Long;
  my %options;
  my $parser=Getopt::Long::Parser->new;
  $parser->configure("pass_through");
  #Getopt::Long::GetOptionsFromArray
  $parser->getoptionsfromarray($options, \%options,
    "workers=i",
    "listener=s@",
    "show:s@",
    "read-size=i"
    
  ) or die "Invalid arguments";

  say "parse in server";
  for my($key, $value)(%options){
    if($key eq "workers"){
      $self->workers=$value<0?undef:$value;
    }
    elsif($key eq "listener"){
      $self->_add_listeners($_) for(@$value);
    }
    elsif($key eq "show"){
      $_options->{show_routes}=$value||".*";
    }
    elsif($key eq "read-size"){
      $_read_size=$value;
    }

    else {
      #Unsupported option
    }
  }

  # Process all sites
  $self->SUPER::process_cli_options($options);
  $self;
}

# Create a new stream connection to a server. Adds the connection to the idle pool
method do_stream_connect {
  Log::OK::TRACE and log_trace __PACKAGE__." do_stream_connect";
  my ($host, $port, $on_connect, $on_error)=@_;
  # Inititiate connection to server. This makes a new connection and adds to the pool

  my $entry; 


  my $id;
  my $socket;

  #$socket=uSAC::IO::socket(AF_INET, SOCK_STREAM, 0);
  $socket=IO::FD::socket(AF_INET, SOCK_STREAM, 0);

  if( $entry=$_host_tables->{$host} and $entry->[uSAC::HTTP::Site::ADDR]){

    # Don't do a name resolve as we already have it.
    # 
    #Create the socket 
    $id=uSAC::IO::connect_addr($socket, $entry->[uSAC::HTTP::Site::ADDR], $on_connect, $on_error);
    
  }
  else {
    $id=uSAC::IO::connect($socket, $host, $port, undef, $on_connect, $on_error);

  }
  $id;
}


method worker_count {
  $_workers= pop;
  $self;
}
1; 
