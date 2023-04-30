use v5.36;
package uSAC::HTTP::Server; 
use feature "try";

use Object::Pad;
use Log::ger;
use Log::OK;

use Socket;
use Socket::More qw<sockaddr_passive parse_passive_spec family_to_string sock_to_string>;

use IO::FD;
use uSAC::IO;
use uSAC::IO::Acceptor;
use uSAC::HTTP::Route;
use Error::Show;

use constant::more {
	"CONFIG::set_no_delay"=> 1
};
use constant::more {
	"CONFIG::single_process"=>1,
	"CONFIG::kernel_loadbalancing"=>1,
};

#Set a logging level if the use application hasn't
use Log::OK {
	lvl=>"warn"
};


use feature qw<refaliasing say state current_sub>;
use constant NAME=>"uSAC";
use constant VERSION=>"v0.1.0";

#our @Subproducts;#=();		#Global to be provided by applcation

use version; our $VERSION = version->declare('v0.1.0');

no warnings "experimental";


use uSAC::HTTP::Site;
use uSAC::HTTP::Constants;
use Hustle::Table;		#dispatching of endpoints


use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK);


use Scalar::Util 'refaddr', 'weaken';

use Socket qw(
  AF_INET
  AF_UNIX
  SOCK_STREAM
  SOCK_DGRAM
  SOL_SOCKET
  SO_REUSEADDR
  SO_REUSEPORT
  TCP_NODELAY
  IPPROTO_TCP
  TCP_NOPUSH 
  TCP_NODELAY
  SO_LINGER
  inet_pton
);

use Carp 'croak';


use uSAC::HTTP::Code ":constants";
use uSAC::HTTP::Header ":constants";
use uSAC::HTTP::Session;
#use uSAC::HTTP::v1_1_Reader;
use uSAC::HTTP::Rex;
use uSAC::MIME;

use Exporter 'import';

our @EXPORT_OK=qw<
  usac_server
  usac_run
  usac_load
  usac_include
  usac_listen
  usac_listen2
  usac_mime_map
  usac_mime_default
  usac_sub_product
  usac_workers
>;

our @EXPORT=@EXPORT_OK;


my $session_id=0;

# Basic handlers
#
# Welcome message
sub _welcome {
  state $data=do{ local $/=undef; <DATA>}; #execute template

  state $sub=sub {
    if($_[CODE]){
      $_[PAYLOAD]=$data;
      &rex_reply_html;
    }
  }
}

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
		state $sub=sub {
			Log::OK::DEBUG and log_debug __PACKAGE__. " DEFAULT HANDLER: ". $_[1]->uri;
			Log::OK::DEBUG and log_debug __PACKAGE__.join $_[REX]->headers->%*;
			$_[PAYLOAD]="NOT FOUND";
			&rex_error_not_found;
		};
}

class uSAC::HTTP::Server :isa(uSAC::HTTP::Site);

no warnings "experimental";
#field $_sites;
field $_host_tables;
field $_cb;
field $_listen;
field $_listen2;
field $_graceful;
field $_aws;
field $_aws2;
field $_fh;
field $_fhs;
field $_fhs2;
field $_fhs3;
field $_backlog;
field $_read_size;
field $_upgraders;
field $_sessions;
field $_active_connections;
field $_total_connections;
field $_active_requests;
field $_zombies;
field $_zombie_limit;
field $_stream_timer;
field $_server_clock;
field $_www_roots;
field $_mime;
field $_workers;
field $_cv;
field $_options :reader;
field $_application_parser;
field $_total_requests;
field $_mime_db;
field $_mime_default;
field $_static_headers :mutator;
#field $_mode           :mutator :param=undef;


BUILD {
	$_mime_db//=uSAC::MIME->new;
	$_mime_default="application/octet-stream";

	$_host_tables={};
  $_zombies=[];
	$_zombie_limit//=100;
	$_static_headers={};#STATIC_HEADERS;

  $self->mode//=0; #Only set to server mode if it hasn't been defined.

	my $default=$self->add_site(uSAC::HTTP::Site->new(id=>"default", host=>"*.*", mode=>$self->mode));
	$default->add_route([$Any_Method], undef, _default_handler);

	$_backlog=4096;
	$_read_size=4096;
	$_workers=undef;
  $_options={};

	#$self->[max_header_size_]=MAX_READ_SIZE;
	$_sessions={};

	$_listen=[];
	$_listen2=[];

}

###############################################################################################################
# sub new {                                                                                                   #
#         my $pkg = shift;                                                                                    #
#         my $self = $pkg->SUPER::new();#bless [], $pkg;                                                      #
#         my %options=@_;                                                                                     #
#                                                                                                             #
#         $self->[host_tables_]={};                                                                           #
#         $self->[cb_]=$options{cb}//sub { (200,"Change me")};                                                #
#         $self->[zombies_]=[];                                                                               #
#         $self->[zombie_limit_]=$options{"zombie_limit"}//100;                                               #
#         $self->[static_headers_]=[];#STATIC_HEADERS;                                                        #
#                                                                                                             #
#         my $default=$self->register_site(uSAC::HTTP::Site->new(id=>"default", host=>"*.*", server=>$self)); #
#         $default->add_route([$Any_Method], undef, _default_handler);                                        #
#                                                                                                             #
#         $self->[backlog_]=4096;                                                                             #
#         $self->[read_size_]=4096;                                                                           #
#         $self->[workers_]=undef;                                                                            #
#   $self->[options_]={};                                                                                     #
#                                                                                                             #
#         #$self->[max_header_size_]=MAX_READ_SIZE;                                                           #
#         $self->[sessions_]={};                                                                              #
#                                                                                                             #
#         $self->[listen_]=[];                                                                                #
#         $self->[listen2_]=[];                                                                               #
#                                                                                                             #
#         $self->mime_db=uSAC::MIME->new;                                                                     #
#         $self->mime_default="application/octet-stream";                                                     #
#         #$self->[mime_lookup_]=$self->mime_db->index;                                                       #
#                                                                                                             #
#         return $self;                                                                                       #
# }                                                                                                           #
###############################################################################################################


method _setup_dgram_passive {
	my ($l)=@_;
	#Create a socket from results from interface
	IO::FD::socket my $fh, $l->{family}, $l->{type}, $l->{protocol} or Carp::croak "listen/socket: $!";

	IO::FD::setsockopt($fh, SOL_SOCKET, SO_REUSEADDR, pack "i", 1);
	
	if($l->{family}== AF_UNIX){
		unlink $l->{path};
	}
	else{
		IO::FD::setsockopt $fh, SOL_SOCKET, SO_REUSEPORT, pack "i", 1;

	}

	defined(IO::FD::bind $fh, $l->{addr})
		or Carp::croak "listen/bind: $!";

	if($l->{family}== AF_UNIX){
		chmod oct('0777'), $l->{path}
			or warn "chmod $l->{path} failed: $!";
	}
	else {

	}

	IO::FD::fcntl $fh, F_SETFL,O_NONBLOCK;
	$_fhs3->{$fh} = $fh;
}


method _setup_stream_passive{
	my ($l)=@_;

	#Create a socket from results from interface
	defined IO::FD::socket my $fh, $l->{family}, $l->{type}, $l->{protocol} or Carp::croak "listen/socket: $!";

	IO::FD::setsockopt($fh, SOL_SOCKET, SO_REUSEADDR, pack "i", 1);
	
	if($l->{family}== AF_UNIX){
		unlink $l->{path};
	}
	else{
		IO::FD::setsockopt $fh, SOL_SOCKET, SO_REUSEPORT, pack "i", 1;
	}


	defined(IO::FD::bind $fh, $l->{addr})
		or Carp::croak "listen/bind: $!";
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
			or Carp::croak "listen/listen on ".( $_).": $!";
	}
}


#Filter the interface listeners to the right place
method do_passive {
  #my $self = shift;
	#Listeners are in interface format
	die "No listeners could be found" unless $_listen2->@*;
	for my $l ($_listen2->@*){
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
  #weaken( my $self = shift );
  \my @zombies=$_zombies; #Alias to the zombie sessions for reuse
  \my %sessions=$_sessions;	#Keep track of the sessions

  my $do_client=$self->make_basic_client;

  my @peers;
  my @afh;
  for my $fl ( values %$_fhs2 ) {
    #TODO: based on per listener settings route to different processing subs
    # eg
    #   http
    #   https
    #   http2/s
    #   sni

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
method make_basic_client{

  #my ($self)=@_;
  \my @zombies=$_zombies;
  \my %sessions=$_sessions;

  my $session;
  unless($_application_parser){
    require uSAC::HTTP::v1_1_Reader;
    $_application_parser=\&uSAC::HTTP::v1_1_Reader::make_parser;
  }
  
  my $parser=$_application_parser; 

  sub {
    my ($fhs, $peers)=@_;

    my $i=0;
    for my $fh(@$fhs){
      #TODO:
      # Need to do OS check here
      #CONFIG::set_no_delay and IO::FD::setsockopt $fh, IPPROTO_TCP, TCP_NODELAY, pack "i", 1 or Carp::croak "listen/so_nodelay $!";


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
      #$active_connections++;
      #$total_connections++;

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

	#ctx is array
	#[$site, $endpoint, $outer, $default_flag]
	#This becomes the value field in hustle table entry
	#[matcher, value, type, default]
	my $table=$_host_tables->{$host}//=[
		Hustle::Table->new($dummy_default), # Table
    {},                                  # Table cache
    undef,                              #  dispatcher
    "",
    [],
    [],
    0

	];

  # NOTE: This is the route context. This is  a back refernce to the table
  # TODO: Possibly weaken this
  push $ctx->@*, $table;

	$table->[0]->add(matcher=>$matcher, value=>$ctx, type=>$type);
}

method rebuild_dispatch {
  #my $self=shift;

  Log::OK::DEBUG and log_debug(__PACKAGE__. " rebuilding dispatch...");
  #Install error routes per site
  #Error routes are added after other routes.

  # Create a special default site for each host that matches any method and uri
  #  An entry is only added if the dummy_defualt is currently the default
  #
  for my $host (keys $_host_tables->%*) {
    Log::OK::TRACE and log_trace(__PACKAGE__. " $host");
    #If the table has a dummy catch all then lets make an fallback
    my $entry=$_host_tables->{$host}; 
    my $last=$entry->[0]->@*-1; #Index of default in hustle table

    if($entry->[0][$last] == $dummy_default){
      Log::OK::TRACE and log_trace(__PACKAGE__. " host table special default. detected. Adding special site");
      my $site=uSAC::HTTP::Site->new(id=>"_default_$host", host=>$host, server=>$self, mode=>$self->mode);
      $site->parent_site=$self;
      $self->add_site($site);
      Log::OK::DEBUG and log_debug "Adding default handler to $host";

      $site->add_route([$Any_Method], undef, _default_handler);
    }
  }


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
    Log::OK::TRACE and  log_trace "IN SERVER CB: @_";

    Log::OK::TRACE and  log_trace values $_host_tables->%*;
    #my ($host, $input);
    
    # input is "method url"
    
    #$table=$lookup{$_[0]//""}//$any_host;
    $table=$_host_tables->{$_[0]//""}//$any_host;
    #say "TABLE IS DEFAULt : ".($table==$any_host);

    #use Data::Dumper;
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
    ($route, $captures);
  };
}


method stop {
  #my $self=shift;
	$_cv->send;
}

method run {
  #my $self=shift;
  my $sig; $sig=AE::signal(INT=>sub {
          $self->stop;
          $sig=undef;
  });

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
			for $_listen2->@*;
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
        
        my $site=$entry->[1][0];


        my $matcher=$entry->[0];
        if(is_regexp $matcher){
          $matcher=regexp_pattern $matcher;
          while($matcher=~s|\(\?\^u\:(.*)\)|$1|){};

        }
        my $key;
        my @a;

        if($site){
          #@a=$entry->[0], $entry->[2], $site->id, $site->prefix;
          #$key=join "-",@a;

          $tab->load([$matcher, $entry->[2], $site->id, $site->prefix, join "\n",$host]);
        }
        else{

          #@a=$entry->[0], $entry->[2], "na", "na";
          #$key=join "-",@a;

          $tab->load([$matcher, $entry->[2], "na", "na", join "\n",$host]);
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


sub usac_server :prototype(&) {
	#my $sub=shift;
	#my $server=$_;
	my $sub=pop;	#Content is the last item
	my %options=@_;
	my $server=$options{parent}//$uSAC::HTTP::Site;

	#my $server=$uSAC::HTTP::Site;
	unless(defined $server and ($server->isa( 'uSAC::HTTP::Site'  ))) {
		#only create if one doesn't exist
		log_info "Creating new server";
		$server=uSAC::HTTP::Server->new(mode=>0);
	}

	#Push the server as the lastest 'site'
	local $uSAC::HTTP::Site=$server;
	$sub->($server);		#run the configuration for the server
	$server;
}

#Attempt to run the server, only if its in DSL mode
sub usac_run {
	my %options=@_;
	my $site=$options{parent}//$uSAC::HTTP::Site;
  $site->parse_cli_options(@ARGV);

	$site->run;

}

#include another config file
#Do so in the callers package namespace
#the package option allows including into that package
sub usac_load {
	my $path=pop;
	my %options=@_;

	$path=uSAC::HTTP::Site::usac_path %options, $path;
	
	$options{package}//=(caller)[0];
	
	#recursivley include files
	if(-d $path){
		#Dir list and contin
		my @files= <"${path}/*">;
		for my $file (@files){
			__SUB__->( %options, $file);
		}
	}
	else{
		#not a dir . do it
		Log::OK::INFO and log_info "Including server script from $path";
    #my $result=
    eval "require '$path'";

    if($@){
      my $context=Error::Show::context;
      log_error "Could not include file: $context";
      die "Could not include file $path";	
    }

	}
}
*usac_include=\*usac_load;

sub usac_listen2 {
	my $spec=pop;		#The spec for interface matching
	my %options=@_;		#Options for creating hosts
	my $site=$options{parent}//$uSAC::HTTP::Site;
	$site->add_listeners(%options, $spec);
}

*usac_listen=*usac_listen2;

#TODO:
# We wany to either specifiy the interface name (ie eth0 wlan0 etc)
# or the specific address which exists on an interface.
# need to look at GETIFADDRS library/syscall;
#
# Use getaddrinfo on supplied arguments. 
#  try for numeric interfaces first  for supplied args
#  then try for hostnames. For each hostname add the numeric  listener
#
#  Stream, dgram listeners And then add protocols
#
#	usac_listener type=>"http3", ssl=>cert,
#		socketopts=>(
#			SOL_SOCKET=>SO_REUSEADDR,	#
#			SOL_SOCKET=>SO_REUSEPORT,	#Important for load balancing
#			IPPROTO_TCP=>TCP_NODELAY,
#		),
#		"address:port";
#
#		#sets up initial server reader, udp port listener and ssl processing
#		#address can be either a hostname, path or ipv4 ipv6 address
#
#	usac_listener type=>"http2", ssl=>cert, "address::port";
#	usac_listener type=>"http1", ssl=>undef, "address::port";
#	

method add_listeners {
  #my $site=shift;
	my $spec=pop;
	my %options=@_;

  my @spec;
  my @addresses;

  my $ref=ref $spec;
  if($ref  and $ref ne "HASH"){
    croak "Listener must be a HASH ref or a sockaddr_passive cli string";

  }
  elsif($ref eq ""){
    @spec=parse_passive_spec($spec);
    #use feature ":all";
    croak  "could not parse listener specification" unless $spec;
  }
  else {
    #Hash
    @spec=($spec);
  }

	@addresses=sockaddr_passive(@spec);
	push $_listen2->@*, @addresses;
}

method listeners:lvalue {
  #my $self=shift;
  $_listen2;
}

sub usac_workers {
	my $workers=pop;	#Content is the last item
	my %options=@_;
	my $site=$options{parent}//$uSAC::HTTP::Site;

	#FIXME
  $site->workers=$workers;
}

method workers: lvalue {
  #my $self=shift;
  my $workers=pop;
  #my %options=@_;
  $_workers=shift;
}


sub usac_sub_product {
	my $sub_product=pop;	#Content is the last item
	my %options=@_;
	my $server=($options{parent}//$uSAC::HTTP::Site)->find_root;
	$server->static_headers={
	  HTTP_SERVER()=>(uSAC::HTTP::Server::NAME."/".uSAC::HTTP::Server::VERSION." ".join(" ", $sub_product) )};
}

sub usac_read_size {
	my $read_size=pop;	#Content is the last item
	my %options=@_;
	my $server=$options{parent}//$uSAC::HTTP::Site;
  $server->read_size=$read_size;

}

method read_size :lvalue{
  #my $self=shift;
  $_read_size;
}

sub usac_application_parser {
	my $parser=pop;	#Content is the last item
	my %options=@_;
	my $server=$options{parent}//$uSAC::HTTP::Site;
  $server->application_parser=$parser;
}

method application_parser :lvalue {
  #my $self=shift;
  $_application_parser;
    
}

method parse_cli_options {
  #my $self=shift;
  my @options=@_?@_:@ARGV;

  #Attempt to parse the CLI options
  require Getopt::Long;
  my %options;

  Getopt::Long::GetOptionsFromArray(\@options, \%options,
    "workers=i",
    "listener=s@",
    "show:s@",
    "read-size=i"
    
  ) or die "Invalid arguments";

  for my($key, $value)(%options){
    if($key eq "workers"){
      $self->workers=$value<0?undef:$value;
    }
    elsif($key eq "listener"){
      $self->add_listeners($_) for(@$value);
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
}


# Client side routing
# Executes a request. the appropriate session and rex are configured 
# at the start of the request. The incomming response calls this pre configured
# value



# Create a new stream connection to a server. Adds the connection to the idle pool
method do_stream_connect {
  Log::OK::TRACE and log_trace __PACKAGE__." do_stream_connect";
  my ($host, $port, $on_connect, $on_error)=@_;
  # Inititiate connection to server. This makes a new connection and adds to the pool

  my $entry; 


  my $id;
  my $socket;

  $socket=uSAC::IO::socket(AF_INET, SOCK_STREAM, 0);

  if( $entry=$_host_tables->{$host} and $entry->[uSAC::HTTP::Site::ADDR]){

    # Don't do a name resolve as we already have it.
    # 
    #Create the socket 
    $id=uSAC::IO::connect_addr($socket, $entry->[uSAC::HTTP::Site::ADDR], $on_connect, $on_error);
    
  }
  else {

    $id=uSAC::IO::connect($socket, $host, $port, $on_connect, $on_error);

  }
  $id;
}

use uSAC::IO;
sub usac_request {

}

method fetch ($resouce, @options) {

}

method request {
  Log::OK::TRACE and log_trace __PACKAGE__." request";
  # Queue a request in host pool and trigger if queue is inactive
  #
  my($host, $method, $uri, $header, $payload, $cb)=@_;

  $header//={};
  $payload//="";
  my $version;
  my $ex;
  my $request_id;
  my $fh;
  my $scheme;
  my $peers;
  my $i;

  my ($__host, $port)=split ":", $host;
  $port//=80;
  my $options;

  # Attempt to connect to host if we have no connections  in the pool
  state $any_host=$_host_tables->{"*.*"};

  my $entry=$_host_tables->{$host}//$any_host;
  
  # We will always have a host table here, event if it is the default one
  #
  
  # Push to queue
  my $details=[$host, $method, $uri, $header, $payload, $cb, $request_id++];

  my $prev_queue_size=$entry->[uSAC::HTTP::Site::REQ_QUEUE]->@*;

  push $entry->[uSAC::HTTP::Site::REQ_QUEUE]->@*, $details;

  # Check the number of items outstnding in the queue vs how many connections we have
  #
  say "CURRENT ACTIVE COUNT IS: $entry->[uSAC::HTTP::Site::ACTIVE_COUNT]";
  my $limit =10;
  if( 
    ($limit<=0 or $entry->[uSAC::HTTP::Site::ACTIVE_COUNT] < $limit)  # Check limit

    ){

      $entry->[uSAC::HTTP::Site::ACTIVE_COUNT]++;

      #Create another connection so long as it is doesn't exceed the limit
      $self->do_stream_connect($__host, $port, sub {
          my ($socket, $addr)=@_;
          $entry->[uSAC::HTTP::Site::ADDR]=$addr;
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
        #if($prev_queue_size == 0){
          #we need to kick up the first request
        $self->_request($entry, $session);
          #}

      },

      sub {
        # connection error
        #
        $entry->[uSAC::HTTP::Site::ACTIVE_COUNT]--;
        say "error callback for stream connect: $_[1]";
        IO::FD::close $_[0]; # Close the socket
        my($route, $captures)=$entry->[uSAC::HTTP::Site::HOST_TABLE_DISPATCH]("$method $uri");

        die "No route found for $host" unless $route;

        $route->[1][ROUTE_ERROR_HEAD]->();
        
        #say $_[1];
        #say Error::Show::context frames=>Devel::StackTrace->new();

      }
    )
  }
  else{
    # Sit tight.. a connection will become available soon.. hopefully!
    Log::OK::TRACE and log_trace __PACKAGE__. " request queued but waiting for in flight to finish";
  }

  $request_id;

}


method _request {
  Log::OK::TRACE and log_trace __PACKAGE__." _request";
  # From the given host table and sesssion attmempt to execute the request stored in $details
  # or of extract from the host queue
  # Schedules the request for the next loop of the event system
  my ($table, $session, $details)=@_;

  #my($host, $port, $method, $uri, $header, $payload, $cb)=@_;

  my $version;
  my $ex;
  #my $id;
  #my $fh;
  my $scheme;
  my $peers;
  my $i;
  
  uSAC::IO::asap {
    $details//=shift($table->[uSAC::HTTP::Site::REQ_QUEUE]->@*);
    unless($details){
      # No more work to do so add the session to the idle pool
      Log::OK::INFO and log_info "No futher requests to process. Return to idle pool";
      push $table->[uSAC::HTTP::Site::IDLE_POOL]->@*, $session;
      $table->[uSAC::HTTP::Site::ACTIVE_COUNT]--;
      return;
    }
    else {
      #TODO Adjust active count
    }

    my $host=$details->[0];
    my $method=$details->[1];
    my $uri=$details->[2];
    my $header=$details->[3];
    my $payload=$details->[4];
    my $cb=$details->[5];

    say "PAYLOAD FOR REQUEST: $payload";
    # At this point there should be at least one available session in the pool for the host

    #say "Idle pool is: ".Dumper $table->[IDLE_POOL];
    #my $session=pop $table->[uSAC::HTTP::Site::IDLE_POOL]->@*;
    #$table->[uSAC::HTTP::Site::ACTIVE_COUNT]++;

    # Do a route lookup
    #
    #say Dumper $details;
    my($route, $captures)=$table->[uSAC::HTTP::Site::HOST_TABLE_DISPATCH]("$method $uri");

    die "No route found for $host" unless $route;

      #  Obtain session or create new. Update with the filehandle
      my %h=();#%$_static_headers;   #Copy static headers



      # Create the REX object
      #
      $ex=$session->exports;
      $version="HTTP/1.1"; # TODO: FIX
      my $rex=uSAC::HTTP::Rex::new("uSAC::HTTP::Rex", $session, \%h, $host, $version, $method, $uri, $ex, $captures);


      # Set the current rex and route for the session.
      # This is needed for the parser in client mode. It makes the route known
      # ahead of time.
      $ex->[3]->$*=$rex;
      $ex->[7]->$*=$route;


      # Call the head of the outerware function
      #
      $route->[1][ROUTE_OUTER_HEAD]($route, $rex, my $code=-1, $header, $payload, $cb);
  };
}

1; 
=head1 NAME

uSAC::HTTP::Server - Streaming HTTP server

=head1 SYNOPSIS

  use EV;
  use AnyEvent;


  use Log::ger;
  use Log::OK;
  use Log::ger::Output "Screen";


  use uSAC::HTTP;

  usac_server {
    usac_listen ...;
      ... 
    usac_run;
  };

=head1 DESCRIPTION

Implements event based HTTP Server, supporting websockets and focusing on
efficient middleware execution to facility data 'streaming';

=head1 API

=head2 DSL

=head3 usac_listen

=head3 usac_host;

=cut

__DATA__
<!doctype html>
<html>
<head>
		<title>Welcome to uSAC HTTP Server</title>
		<style>
			html, body, div {
				display: flex;
				flex:1;
				align-content: center;
				align-items: center;
			}
			html {
				height: 100%;

			}

		</style>
	</head>
	<body style="height: 100%;">
		<div style="flex-direction: column;"> 
			Welcome to uSAC HTTP Server</div>
	

</body>
</html>
