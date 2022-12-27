use v5.36;
package uSAC::HTTP::Server; 
use feature "try";

use Log::ger;
use Log::OK;
use Socket;
use Socket::More qw<sockaddr_passive parse_passive_spec family_to_string sock_to_string>;
use IO::FD;
use uSAC::IO::Acceptor;
use Error::ShowMe;

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
use constant VERSION=>"0.1";

#our @Subproducts;#=();		#Global to be provided by applcation

use version; our $VERSION = version->declare('v0.1.0');

no warnings "experimental";
use parent 'uSAC::HTTP::Site';

use uSAC::HTTP::Site;

use uSAC::HTTP::Code ":constants";
use uSAC::HTTP::Constants;

use Hustle::Table;		#dispatching of endpoints

use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK);


#use AnyEvent;
use Scalar::Util 'refaddr', 'weaken';
use Socket qw(AF_INET AF_UNIX SOCK_STREAM SOCK_DGRAM SOL_SOCKET SO_REUSEADDR SO_REUSEPORT TCP_NODELAY IPPROTO_TCP TCP_NOPUSH TCP_NODELAY SO_LINGER
inet_pton);

use Carp 'croak';

#use constant MAX_READ_SIZE => 128 * 1024;

#Class attribute keys
#max_header_size_
#

use constant KEY_OFFSET=> uSAC::HTTP::Site::KEY_OFFSET+uSAC::HTTP::Site::KEY_COUNT;

use enum (
	"sites_=".KEY_OFFSET, qw<host_tables_ cb_ listen_ listen2_ graceful_ aws_ aws2_ fh_ fhs_ fhs2_ fhs3_ backlog_ read_size_ upgraders_ sessions_ active_connections_ total_connections_ active_requests_ zombies_ zombie_limit_ stream_timer_ server_clock_ www_roots_ static_headers_ mime_ workers_ cv_ total_requests_>
);


use constant KEY_COUNT=> total_requests_ - sites_+1;

use uSAC::HTTP::Code ":constants";
use uSAC::HTTP::Header ":constants";
use uSAC::HTTP::Session;
use uSAC::HTTP::v1_1_Reader;
use uSAC::HTTP::Rex;
use uSAC::MIME;
use Exporter 'import';

our @EXPORT_OK=qw<usac_server usac_run usac_include usac_listen usac_listen2 usac_mime_map usac_mime_default usac_sub_product usac_workers>;
our @EXPORT=@EXPORT_OK;



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


sub new {
	my $pkg = shift;
	my $self = $pkg->SUPER::new();#bless [], $pkg;
	my %options=@_;

	$self->[host_tables_]={};
	$self->[cb_]=$options{cb}//sub { (200,"Change me")};
	$self->[zombies_]=[];
	$self->[zombie_limit_]=$options{"zombie_limit"}//100;
	$self->[static_headers_]=[];#STATIC_HEADERS;

	my $default=$self->register_site(uSAC::HTTP::Site->new(id=>"default", host=>"*.*", server=>$self));
	$default->add_route([$Any_Method], undef, _default_handler);

	$self->[backlog_]=4096;
	$self->[read_size_]=4096;
	$self->[workers_]=undef;

	#$self->[max_header_size_]=MAX_READ_SIZE;
	$self->[sessions_]={};

	$self->[listen_]=[];
	$self->[listen2_]=[];

	$self->mime_db=uSAC::MIME->new;
	$self->mime_default="application/octet-stream";
	#$self->[mime_lookup_]=$self->mime_db->index;
	return $self;
}


sub _setup_dgram_passive {
	my ($self,$l)=@_;
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
	$self->[fhs3_]{$fh} = $fh;
}


sub _setup_stream_passive{
	my ($self, $l)=@_;

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

	$self->[fhs2_]{$fh} = $fh;


	#Finally run the listener
	for ( values  %{ $self->[fhs2_] } ) {
		IO::FD::listen $_, $self->[backlog_]
			or Carp::croak "listen/listen on ".( $_).": $!";
	}
}


#Filter the interface listeners to the right place
sub do_passive {
	my $self = shift;
	#Listeners are in interface format
	die "No listeners could be found" unless $self->[listen2_]->@*;
	for my $l ($self->[listen2_]->@*){
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
sub prepare {
	#setup timer for constructing date header once a second
	my ($self)=shift;

  #Start the acceptors running on this worker 
  $_->start for(values $self->[aws_]->%*);
  
  #Setup the watchdog timer for the any active connections
	my $interval=1;
	my $timeout=20;
	$self->[server_clock_]=time;	

	#Timeout timer
	#
  $SIG{ALRM}=
  #$self->[stream_timer_]=AE::timer 0, $interval,
  sub {
		#iterate through all connections and check the difference between the last update
		$self->[server_clock_]+=$interval;
		#and the current tick
		my $session;
		for(keys $self->[sessions_]->%*){
			$session=$self->[sessions_]{$_};

			if(($self->[server_clock_]-$session->time)> $timeout){
				Log::OK::DEBUG and log_debug "DROPPING ID: $_";
				$session->closeme=1;
				$session->drop;
			}
		}
		
	  alarm	 $interval;# if $self->[sessions_]->%*; #only start interval if something to watch?
	};
  
  alarm $interval;

}

#
# Iterate over passive sockets and setup an asyncrhonous acceptor
# 
sub do_accept{
  #Accept is only for SOCK_STREAM 
  state $seq=0;
  Log::OK::INFO and log_info __PACKAGE__. " Accepting connections";
  weaken( my $self = shift );
  \my @zombies=$self->[zombies_]; #Alias to the zombie sessions for reuse
  \my %sessions=$self->[sessions_];	#Keep track of the sessions

  my $do_client=$self->make_basic_client;

  my @peers;
  my @afh;
  for my $fl ( values %{ $self->[fhs2_] }) {
    $self->[aws_]{ $fl } =my $acceptor=uSAC::IO::Acceptor->create(fh=>$fl, on_accept=>$do_client, on_error=>sub {});
    #$acceptor->start;
  }
  Log::OK::INFO and log_info "SETUP PASSIVE COMPLETE";
}



sub make_do_dgram_client {
	#A single dgram listener is all thats required. it needs to call.
	#todo
}

#
#Returns a sub for processing new TCP client connections
#
sub make_basic_client{

  my ($self)=@_;
  \my @zombies=$self->[zombies_];
  \my %sessions=$self->[sessions_];

  my $session;
  my $seq=0;

  sub {
    my ($fhs, $peers)=@_;

    my $i=0;
    for my $fh(@$fhs){
      #TODO:
      # Need to do OS check here
      #CONFIG::set_no_delay and IO::FD::setsockopt $fh, IPPROTO_TCP, TCP_NODELAY, pack "i", 1 or Carp::croak "listen/so_nodelay $!";


      my $id = ++$seq;
      my $scheme="http";

      Log::OK::DEBUG and log_debug "Server new client connection: id $id";

      if(@zombies){
        $session=pop @zombies;
        $session->revive($id, $fh, $scheme, $peers->[$i]);
      }
      else {
        $session=uSAC::HTTP::Session->new;
        $session->init($id,$fh,$self->[sessions_],$self->[zombies_],$self, $scheme, $peers->[$i]);
        $session->push_reader(make_reader $session, MODE_SERVER);
      }
      $i++;
      $sessions{ $id } = $session;

      #$active_connections++;
      #$total_connections++;

    }
    @{$fhs}=();
    @{$peers}=();
  }
}

sub current_cb {
	shift->[cb_];
}


sub static_headers {
	shift->[static_headers_];
}

sub add_host_end_point{
	my ($self, $host, $matcher, $ctx, $type)=@_;

	#ctx is array
	#[$site, $endpoint, $outer, $default_flag]
	#This becomes the value field in hustle table entry
	#[matcher, value, type, default]
	my $table=$self->[host_tables_]{$host}//=[
		Hustle::Table->new($dummy_default),{}
	];
	$table->[0]->add(matcher=>$matcher, value=>$ctx, type=>$type);
}

#registers a site object with the server
#returns the object
sub register_site {
	my $self=shift;
	my $site=shift;
	#$site->[uSAC::HTTP::server_]=$self;
	$site->server=$self;
	my $name=$site->id;#$site->[uSAC::HTTP::id_];
	$self->[sites_]{$name}=$site;
	$site;
}
#returns the default site
sub default_site {
	my $self=shift;
	$self->[sites_]{default};
}

#returns the site registered with the specified name
#Returns default if not specififed
sub site {
	my $self=shift;
	my $name=shift;
	$self->[sites_]{$name//"default"}
}


sub rebuild_dispatch {
  my $self=shift;

  Log::OK::INFO and log_info(__PACKAGE__. " rebuilding dispatch...");
  #Install error routes per site
  #Error routes are added after other routes.

  #Create a special default site for each host that matches any method and uri
  for my $host (keys $self->[host_tables_]->%*) {
    #If the table has a dummy catch all then lets make an fallback
    my $entry=$self->[host_tables_]{$host};
    my $last=$entry->[0]->@*-1;
    if($entry->[0][$last] == $dummy_default){

      my $site=uSAC::HTTP::Site->new(id=>"_default_$host", host=>$host, server=>$self);
      $site->parent_site=$self;
      $self->register_site($site);
      Log::OK::TRACE and log_trace "Adding default handler to $host";

      $site->add_route([$Any_Method], undef, _default_handler);
    }
  }


  my %lookup=map {
      $_, [
      #table
      $self->[host_tables_]{$_}[0]->prepare_dispatcher(cache=>$self->[host_tables_]{$_}[1]),
      #cache for table
      $self->[host_tables_]{$_}[1]
      ]
    } keys $self->[host_tables_]->%*;

    #
    # Parser call the following to identify / match a route for header and path
    # information. The route contains the middlewares prelinked to process the
    # requests
    #
  $self->[cb_]=sub {
    #my ($host, $input, $rex)=@_;#, $rex, $rcode, $rheaders, $data, $cb)=@_;

    my $table=$lookup{$_[0]}//$lookup{"*.*"};
    (my $route, my $captures)= $table->[0]($_[1]);

    #Hustle table entry structure:
    #[matcher, value, type default]
    #
    #ctx/value is  a 'route' structure:
    #[site, linked_innerware, linked_outerware, counter]
    #  0 ,		1 	,	2		,3	, 4

    Log::OK::DEBUG and log_debug __PACKAGE__." ROUTE: ".join " ,",$route;
    Log::OK::DEBUG and log_debug __PACKAGE__." ROUTE: ".join " ,",$route->@*;

    #
    # Increment the counter on the route
    #
    $route->[1][4]++;	

    #
    # NOTE: MAIN ENTRY TO  PROCESSING CHAIN / MIDDLEWARE
    # The linked innerware, the route handler and outerware are
    # triggered from here
    # Default Result code is HTTP_OK and a new set of empty headers which
    #
    #$route->[1][1]($route, $rex, my $code=$rcode//HTTP_OK, $rheaders//[],$data//="",$cb);
    #

    # TODO: Better Routing Cache management.
    # if the is_default flag is set, this is an unkown match.
    # so do not cache it

    delete $table->[1]{$_[1]} if $route->[3];
    #return the entry sub for body forwarding
    ($route, $captures);
  };
}


sub stop {
	my $self=shift;
	$self->[cv_]->send;
}

sub run {
	my $self=shift;
	Log::OK::INFO and log_info(__PACKAGE__. " starting server...");
        #######################################
        # my $sig; $sig=AE::signal(INT=>sub { #
        #         $self->stop;                #
        #         $sig=undef;                 #
        # });                                 #
        #######################################

	$self->rebuild_dispatch;

	$self->do_passive;
	$self->do_accept;

	$self->dump_listeners;
	$self->dump_routes;
  
  #TODO: Preforking server
  #Seems like there are no 'thundering herds' in linux and darwin
  #Calles to accept are serialised. Use SO_REUSEPORT for 'zero' downtime
  #server reloads

  if(not defined($self->[workers_]) or $self->[workers_]<0){
    #Attempt to auto pick the number of workers based on cpu information
    try {
      require Sys::Info;
      my $info=Sys::Info->new;
      $self->[workers_]=$info->device("cpu")->count;
      Log::OK::WARN and log_warn "Attempting to quess a nice worker count...";

    }
    catch($e){
      $self->[workers_]=0;
      Log::OK::WARN and log_warn "Error guessing worker count. Running in single process mode (workers =0)";
    }
  }
  if($self->[workers_]){
    Log::OK::INFO and log_info "Running $self->[workers_] workers + manager";
  }
  else {
    Log::OK::INFO and log_info "Running single process mode";
  }

  if($self->[workers_]){
    for(1..$self->[workers_]){
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
	my $cv=AE::cv;
	$self->[cv_]=$cv;
	$cv->recv();
}



sub dump_listeners {
	#Generate a table of all the listeners
	
	my ($self)=@_;
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
			for $self->[listen2_]->@*;
			#$tab->load(@data);
		Log::OK::INFO and log_info join "", $tab->table;

	}
	catch($e){
		Log::OK::ERROR and log_error "Could not load Text::Table for listener dumping";
	}
}

sub dump_routes {
	my ($self)=@_;
	for my $host (sort keys $self->[host_tables_]->%*){
		my $table= $self->[host_tables_]{$host};
		my $tab=Text::Table->new("Match", "Match Type", "Site ID", "Prefix", "Host");
		#table is hustle table and cache entry
		for my $entry ($table->[0]->@*){
			my $site=$entry->[1][0];
      if($site){
        $tab->load([$entry->[0], $entry->[2], $site->id, $site->prefix, join "\n",$host]);
      }
      else{
        $tab->load([$entry->[0], $entry->[2], "na", "na", join "\n",$host]);
      }

		}
		Log::OK::INFO and log_info join "", $tab->table;

	}

	#Make seperate tables by site?
	#sort by group by method

}

sub list_routes {
	#dump all routes	
}
######################################
#                                    #
# sub mime_default: lvalue {         #
#         $_[0]->site->mime_default; #
# }                                  #
# sub mime_db: lvalue {              #
#         $_[0]->site->mime_db;      #
# }                                  #
# sub mime_lookup: lvalue {          #
#         $_[0]->site->mime_lookup;  #
# }                                  #
######################################

#declarative setup


#########################################################
# sub usac_host {                                       #
#         my $host=pop;   #Content is the last item     #
#         my %options=@_;                               #
#         my $self=$options{parent}//$uSAC::HTTP::Site; #
#         push $self->site->host->@*, @_;               #
# }                                                     #
#########################################################

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
		$server=uSAC::HTTP::Server->new();
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
sub usac_include {
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
		my $result=eval "require '$path'";

			if(my $context=Error::ShowMe::context $path){
				log_error "Could not include file $path: $context";
				die "Could not include file $path $!";	
			}

	}
}

sub usac_listen2 {
	my $spec=pop;		#The spec for interface matching
	my %options=@_;		#Options for creating hosts
	my $site=$options{parent}//$uSAC::HTTP::Site;
	$site->add_listeners(%options,$spec);
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

sub add_listeners {
	my $site=shift;
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
	push $site->[listen2_]->@*, @addresses;
}

sub listeners:lvalue {
  my $self=shift;
  $self->[listen2_];
}

sub usac_workers {
	my $workers=pop;	#Content is the last item
	my %options=@_;
	my $site=$options{parent}//$uSAC::HTTP::Site;

	#FIXME
  $site->workers=$workers;
}

sub workers: lvalue {
  my $self=shift;
  my $workers=pop;
  my %options=@_;
  $self->[workers_]=shift;
}


sub usac_sub_product {
	my $sub_product=pop;	#Content is the last item
	my %options=@_;
	my $server=$options{parent}//$uSAC::HTTP::Site;
	$server->[static_headers_]=[
	HTTP_SERVER()=>(uSAC::HTTP::Server::NAME."/".uSAC::HTTP::Server::VERSION." ".join(" ", $sub_product) )];
}


sub parse_cli_options {
  my $self=shift;
  my @options=@_;

  #Attempt to parse the CLI options
  require Getopt::Long;
  my %options;
  Getopt::Long::GetOptionsFromArray \@options,\%options,
    "workers=i",
    "listener=s@"
  ;

  for my($key,$value)(%options){
    if($key eq "workers"){
      $self->workers=$value<0?undef:$value;
    }
    elsif($key eq "listener"){
      $self->add_listeners($_) for(@$value);
    }
    else {
      #Unsupported option
    }
  }
}

1; 
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
