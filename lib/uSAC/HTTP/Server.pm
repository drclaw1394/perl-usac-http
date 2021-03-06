package uSAC::HTTP::Server; 
use strict;
use warnings;

use Log::ger;
use Log::OK;

#use constant "OS::darwin"=>$^O =~ /darwin/;
#use constant "OS::linux"=>0;
#
use constant::more {
	"CONFIG::set_nonblock"=> $^O eq "linux",
	"CONFIG::set_no_delay"=> 1
};
use constant::more {
	"CONFIG::single_process"=>1,
	"CONFIG::kernel_loadbalancing"=>1,
};
use Log::OK {
	lvl=>"warn"
};
use URI;

use feature qw<refaliasing say state current_sub>;
use Try::Catch;
#use IO::Handle;
use constant NAME=>"uSAC";
use constant VERSION=>"0.1";
our @Subproducts;#=();		#Global to be provided by applcation

use version;our $VERSION = version->declare('v0.1');
#use  v5.24;
no warnings "experimental";
use parent 'uSAC::HTTP::Site';
use uSAC::HTTP::Site;

use Hustle::Table;		#dispatching of endpoints

use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK);


use AnyEvent;
use AnyEvent::Socket;
use AnyEvent::Handle;
use Scalar::Util 'refaddr', 'weaken';
use Errno qw(EAGAIN EINTR);
use AnyEvent::Util qw(WSAEWOULDBLOCK AF_INET6 fh_nonblocking);
use Socket qw(AF_INET AF_UNIX SOCK_STREAM SOCK_DGRAM SOL_SOCKET SO_REUSEADDR SO_REUSEPORT TCP_NODELAY IPPROTO_TCP TCP_NOPUSH TCP_NODELAY SO_LINGER
inet_pton);

use File::Basename qw<dirname>;
use File::Spec::Functions qw<rel2abs catfile catdir>;
use Carp 'croak';

use Data::Dumper;
#use constant MAX_READ_SIZE => 128 * 1024;

#Class attribute keys
#max_header_size_
#

use constant KEY_OFFSET=> uSAC::HTTP::Site::KEY_OFFSET+uSAC::HTTP::Site::KEY_COUNT;

use enum (
	"host_=".KEY_OFFSET, qw<port_ enable_hosts_ sites_ host_tables_ cb_ listen_ graceful_ aws_ fh_ fhs_ backlog_ read_size_ upgraders_ sessions_ active_connections_ total_connections_ active_requests_ zombies_ zombie_limit_ stream_timer_ server_clock_ www_roots_ static_headers_ mime_ workers_ cv_ total_requests_>
);

use constant KEY_COUNT=> total_requests_ - host_+1;

use uSAC::HTTP::Code ":constants";
use uSAC::HTTP::Header ":constants";
use uSAC::HTTP::Session;
#use uSAC::HTTP::v1_1;
use uSAC::HTTP::v1_1_Reader;
use uSAC::HTTP::Rex;
use uSAC::MIME;
use Exporter 'import';

our @EXPORT_OK=qw<usac_server usac_include usac_listen usac_mime_map usac_mime_default usac_sub_product>;
our @EXPORT=@EXPORT_OK;



# Basic handlers
#
# Welcome message
sub _welcome {
	state $data;
	unless($data){
		local $/=undef;
		$data=<DATA>;

		#execute template

	}

	state $sub=sub {
		rex_reply_html @_, $data;	
		#rex_write @_, HTTP_OK, {HTTP_CONTENT_LENGTH, length($data),}, $data;
		return; #Enable caching
	}
}

#if nothing else on this server matches, this will run
#And if that happens it it most likley a protocol error
#ie expecting a request line but getting something else
sub _default_handler {
		state $sub=sub {
			#Log::OK::TRACE and log_trace "DEFAULT HANDLER FOR TABLE";
			Log::OK::DEBUG and log_debug __PACKAGE__. " DEFAULT HANDLER: ". $_[1]->uri;
			Log::OK::DEBUG and log_debug __PACKAGE__.join $_[1]->headers->%*;
			say join ", ", @_;
			&rex_error_not_found;
		};
}

sub new {
	my $pkg = shift;
	my $self = $pkg->SUPER::new();#bless [], $pkg;
	my %options=@_;

	$self->[host_]=$options{host}//"0.0.0.0";
	$self->[port_]=$options{port}//8080;
	$self->[enable_hosts_]=1;#$options{enable_hosts};
	$self->[host_tables_]={};
	$self->[cb_]=$options{cb}//sub { (200,"Change me")};
	$self->[zombies_]=[];
	$self->[zombie_limit_]=$options{"zombie_limit"}//100;
	$self->[static_headers_]=[];#STATIC_HEADERS;
	$self->register_site(uSAC::HTTP::Site->new(id=>"default", host=>"*.*"));#,host=>'[^ ]+'));
	$self->[backlog_]=4096;
	$self->[read_size_]=4096;
	$self->[workers_]=1;
	#$self->[max_header_size_]=MAX_READ_SIZE;
	$self->[sessions_]={};

	$self->[listen_]=[];

	$self->mime_db=uSAC::MIME->new;
	$self->mime_default="application/octet-stream";
	#$self->[mime_lookup_]=$self->mime_db->index;
	return $self;
}

sub listen_inet {

}


sub listen {
	my $self = shift;
	Log::OK::INFO and log_info __PACKAGE__." setting up listeners...";
	for my $listen (@{ $self->[listen_] }) {
		say ref $listen;
		my ($host,$service) =($listen->host, $listen->port);#split ':',$listen,2;

		#$service = $self->[port_] unless length $service;
		#$host = $self->[host_] unless length $host;
		
		#$host = $AnyEvent::PROTOCOL{ipv4} < $AnyEvent::PROTOCOL{ipv6} && AF_INET6 ? "::" : "0" unless length $host;
		
		#here we figure out the addressing types

		say "Host: $host, port: $service";
		my $ipn;
		my $af;
		if($ipn=inet_pton(AF_INET6, $host)){
			
			$af=AF_INET6;
		}
		elsif($ipn=inet_pton(AF_INET, $host)){

			$af=AF_INET;
		}
		elsif($host !~ /:\d+$/){
			#try unix socket here
			say $host;
			say "TRY UNIX SOCKET";
			$af=AF_UNIX;
		}
		else{
			#not supported
			die "Could not parse address for listener: $_";
		}
			
		#my $ipn = parse_address $host
		#or Carp::croak "$self.listen: cannot parse '$host' as host address";
		
		#my $af = address_family $ipn;



		
		Carp::croak "listen/socket: address family not supported"
			if AnyEvent::WIN32 && $af == AF_UNIX;
		
		socket my $fh, $af, SOCK_STREAM, 0 or Carp::croak "listen/socket: $!";
		
		if ($af == AF_INET || $af == AF_INET6) {
			if($self->[workers_]>1 or 1){
			setsockopt $fh, SOL_SOCKET, SO_REUSEADDR, 1
				or Carp::croak "listen/so_reuseaddr: $!"
					unless AnyEvent::WIN32; 

			setsockopt $fh, SOL_SOCKET, SO_REUSEPORT, 1
				or Carp::croak "listen/so_reuseport: $!"
					unless AnyEvent::WIN32; 
			}
			else {
				say STDERR "Socket reuse not enabled. (ie only 1 worker)";
			}

			setsockopt $fh, IPPROTO_TCP, TCP_NODELAY, 1
				or Carp::croak "listen/so_nodelay $!"
					unless AnyEvent::WIN32; 
			
                        ##########################################################################
                        # unless ($service =~ /^\d*$/) {                                         #
                        #         $service = (getservbyname $service, "tcp")[2]                  #
                        #                 or Carp::croak "tcp_listen: $service: service unknown" #
                        # }                                                                      #
                        ##########################################################################
		} elsif ($af == AF_UNIX) {
			unlink $service;
		}
		log_info "Service: $service, host $host";
		bind $fh, AnyEvent::Socket::pack_sockaddr( $service, $ipn )
			or Carp::croak "listen/bind on ".eval{Socket::inet_ntoa($ipn)}.":$service: $!";
		
		if ($host eq 'unix/') {
			chmod oct('0777'), $service
				or warn "chmod $service failed: $!";
		}
		
		fh_nonblocking $fh, 1;
	
		$self->[fh_] ||= $fh; # compat
		$self->[fhs_]{fileno $fh} = $fh;
	}
	
	$self->prepare();
	
	for ( values  %{ $self->[fhs_] } ) {
		listen $_, $self->[backlog_]
			or Carp::croak "listen/listen on ".(fileno $_).": $!";
	}
	
	return wantarray ? do {
		#my ($service, $host) = AnyEvent::Socket::unpack_sockaddr( getsockname $self->[fh_] );
		#(format_address $host, $service);
		();
	} : ();
}

sub prepare {
	#setup timer for constructing date header once a second
	my ($self)=shift;
	my $interval=1;
	my $timeout=20;
	$self->[server_clock_]=time;	

	#Timeout timer
	#
	$self->[stream_timer_]=AE::timer 0,$interval, sub {
		#iterate through all connections and check the difference between the last update
		$self->[server_clock_]+=$interval;
		#and the current tick
		my $session;
		for(keys $self->[sessions_]->%*){
			$session=$self->[sessions_]{$_};

			if(($self->[server_clock_]-$session->time)> $timeout){
				Log::OK::DEBUG and log_debug "DROPPING ID: $_";
				#$session->[uSAC::HTTP::Session::closeme_]=1;
				#$session->[uSAC::HTTP::Session::dropper_]->();
				$session->closeme=1;
				$session->drop;
				#delete $self->[sessions_]{$_};
			}
		}
		
		
	};

        # FD recieve
        #open child pipe
        my $sfd;
        my $rfd;
        my $socket;
	return unless $socket;
	my $do_client=$self->make_do_client;
        my $watcher; $watcher=AE::io $socket, 0, sub {
                #fd is readable.. attempt to read
                $rfd=IO::FDPass::recv $sfd;
                if(defined $rfd){
                        #New fd to play with
			$do_client->($rfd);
                }
                elsif($! == EAGAIN or $! ==EINTR){
                        return;
                }
                else {
                        #Actuall error
                        #TODO
                }

        };
}

sub make_sysaccept {
	#attempt a syscall to accept
	#
	my $fh=shift;

	my $syscall_number =30; #macos
	my $addr_len=length AnyEvent::Socket::pack_sockaddr( 80, parse_address("127.0.0.1"));
	my $packed_address=" " x $addr_len;
	my $i=pack("i*",$addr_len);
	my $fn=fileno($fh);

	sub {
		my $handle;
		my $result=syscall $syscall_number, $fn, $packed_address, $i;
		if($result<0){
			#say "Syscall error: $result: $!";
		}
		else {
			#open from fd
			$handle=IO::Handle->new_from_fd($result ,"<");
			#open $handle, "<&=$result";
		}
		return $handle;
	}

}

sub accept {
	state $seq=0;
	Log::OK::INFO and log_info __PACKAGE__. " Accepting connections";
	weaken( my $self = shift );
	\my @zombies=$self->[zombies_];
	\my %sessions=$self->[sessions_];
	my $do_client=$self->make_do_client;

	my $child_index;
	\my @children=[];

	for my $fl ( values %{ $self->[fhs_] }) {
		$self->[aws_]{ fileno $fl } = AE::io $fl, 0, sub {
			my $peer;
			while(($peer = accept my $fh, $fl)){
				#last unless $fh;

				CONFIG::kernel_loadbalancing and $do_client->($fh) and next;

				#!CONFIG::kernel_loadbalancing and IO::FDPass::send $children[$child_index++%@children], $fh;
			}
		};
	}
}

sub as_satellite {
	#Connect to unix socket, which master is listening to
}
sub as_central {
	#Create a unix socket and start accepting connections from worker
	
}



sub make_do_client{

	my ($self)=@_;
	\my @zombies=$self->[zombies_];
	\my %sessions=$self->[sessions_];

	my $session;
	my $seq=0;
	sub {
		my $fh=shift;

		#while ($fl and ($peer = accept my $fh, $fl)) {

		#binmode	$fh, ":raw";

		#Linux does not inherit the socket flags from parent socket. But BSD does.
		#Compile time disabling with constants
		CONFIG::set_nonblock and fcntl $fh, F_SETFL,O_NONBLOCK;

		#TODO:
		# Need to do OS check here
		CONFIG::set_no_delay and setsockopt $fh, IPPROTO_TCP, TCP_NODELAY, 1 or Carp::croak "listen/so_nodelay $!";
		#setsockopt $fh, IPPROTO_TCP, TCP_NOPUSH, 1 or die "error setting no push";


		my $id = ++$seq;
		my $scheme="http";

		Log::OK::DEBUG and log_debug "Server new client connection: id $id";
		if(@zombies){
			$session=pop @zombies;
			#uSAC::HTTP::Session::revive $session, $id, $fh, $scheme;
			$session->revive($id, $fh, $scheme);
		}
		else {
			#$session=uSAC::HTTP::Session::new(undef,$id,$fh,$self->[sessions_],$self->[zombies_],$self, $scheme);
			$session=uSAC::HTTP::Session->new;
			$session->init($id,$fh,$self->[sessions_],$self->[zombies_],$self, $scheme);
			#uSAC::HTTP::Session::push_reader $session, make_reader $session, MODE_SERVER;
			$session->push_reader(make_reader $session, MODE_SERVER);
		}

		$sessions{ $id } = $session;
		#$active_connections++;
		#$total_connections++;

	}
}

sub current_cb {
	shift->[cb_];
}
sub enable_hosts {
	shift->[enable_hosts_];
}

sub static_headers {
	shift->[static_headers_];
}
#########################################################################
# sub add_end_point{                                                    #
#         my ($self,$matcher,$end, $ctx)=@_;                            #
#         $self->[table_]->add(matcher=>$matcher,sub=>$end, ctx=>$ctx); #
# }                                                                     #
#########################################################################
sub add_host_end_point{
	my ($self, $host, $matcher, $ctx, $type)=@_;

	Log::OK::TRACE and log_trace Dumper $matcher;
	my $table=$self->[host_tables_]{$host}//=[
		Hustle::Table->new(sub {log_error "Should not use table default dispatcher: ". $_[1]->[uSAC::HTTP::Rex::uri_]})
		,{}
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

#Duck type as a site 
#######################################
# sub add_route {                     #
#         my $self=shift;             #
#         $self->site->add_route(@_); #
# }                                   #
#                                     #
#                                     #
#                                     #
# sub host {                          #
#         return $_[0]->site->host;   #
# }                                   #
# sub innerware {                     #
#         $_[0]->site->innerware;     #
# }                                   #
# sub outerware{                      #
#         $_[0]->site->outerware;     #
# }                                   #
#######################################


sub rebuild_dispatch {
	my $self=shift;

	Log::OK::INFO and log_info(__PACKAGE__. " rebuilding dispatch...");
	#here we add the unsupported methods to the table before building it
	#Note: this is different to a unfound URL resource.
	#These give a method not supported error, while an unfound resource is a
	#not found error
	#
	#Because of the general matching, they are added to the table after all sites
	#have positive matches installed.
	#
	for(keys $self->[sites_]->%*){
		for ($self->[sites_]{$_}->unsupported->@*){
			Log::OK::TRACE and log_trace "Adding Unmatched endpoints";
			$self->add_host_end_point($_->@*);
		}
	}

	#Create a special default site for each host that matches any method and uri
	for my $host (keys $self->[host_tables_]->%*) {

		my $site=uSAC::HTTP::Site->new(id=>"_default_$host", host=>$host, server=>$self);
		$site->parent_site=$self;
		#$self->register_site($site);
		Log::OK::TRACE and log_trace "Adding default handler to $host";

		$site->add_route($Any_Method, qr|.*|, _default_handler);
	}

	my $site=uSAC::HTTP::Site->new(id=>"_default_*.*", host=>"*.*", server=>$self);
	$site->parent_site=$self;
	#$self->register_site($site);
	Log::OK::TRACE and log_trace "Adding default handler to *.*";

	$site->add_route($Any_Method, qr|.*|, _default_handler);


	my %lookup=map {
		$_, [
			$self->[host_tables_]{$_}[0]->prepare_dispatcher(cache=>$self->[host_tables_]{$_}[1]),
			$self->[host_tables_]{$_}[1]
			]
		}
		keys $self->[host_tables_]->%*;

	$self->[cb_]=sub {
		my ($host, $input, $rex)=@_;

		my $table=$lookup{$host}//$lookup{"*.*"};
		(my $route, $rex->[uSAC::HTTP::Rex::captures_])= $table->[0]($input);

		$route->[1][4]++;
		$route->[1][1]($route,$rex);

		#TODO: Better Routing Cache management.
		if($route->[3]){
			say "deleting default";
			delete $table->[1]{$route->[0]}
		}
	};
}


sub stop {
	my $self=shift;
	$self->[cv_]->send;
}
sub run {
	my $self=shift;
	my $cv=AE::cv;
	Log::OK::INFO and log_info(__PACKAGE__. " starting server...");
	$self->[cv_]=$cv;
	my $sig; $sig=AE::signal(INT=>sub {
		$self->stop;
		$sig=undef;
	});
	unless($self->[listen_] and $self->[listen_]->@*){
		Log::OK::FATAL and log_fatal "NO listeners defined";
		die "no Listeners defined";
	}
	#TODO: check for duplicates
	
        #################################################################################################
        # if (exists $self->[listen_]) {                                                                #
        #         $self->[listen_] = [ $self->[listen_] ] unless ref $self->[listen_];                  #
        #         my %dup;                                                                              #
        #         for (@{ $self->[listen_] }) {                                                         #
        #                 if($dup{ lc $_ }++) {                                                         #
        #                         croak "Duplicate host $_ in listen\n";                                #
        #                 }                                                                             #
        #                 my ($h,$p) = split ':',$_,2;                                                  #
        #                 $h = '0.0.0.0' if $h eq '*';                                                  #
        #                 $h = length ( $self->[host_] ) ? $self->[host_] : '0.0.0.0' unless length $h; #
        #                 $p = length ( $self->[port_] ) ? $self->[port_] : 8080 unless length $p;      #
        #                 $_ = join ':',$h,$p;                                                          #
        #         }                                                                                     #
        #         ($self->[host_],$self->[port_]) = split ':',$self->[listen_][0],2;                    #
        # }                                                                                             #
        # else {                                                                                        #
        #         $self->[listen_] = [ join(':',$self->[host_],$self->[port_]) ];                       #
        # }                                                                                             #
        #################################################################################################
	
        ###################################################################
        # #=======CATCH ALL                                               #
        # #Add a catch all route to the default site.                     #
        # #As this is always the last route added, it will be tested last #
        # #Middleware for the default site is applicable to this handler  #
        # #                                                               #
        # my $site=$self->site;#uSAC::HTTP::Site->new(server=>$self);     #
        #                                                                 #
        # unshift $site->host->@*, "[^ ]+";       #match any host         #
        # $site->add_route($Any_Method, qr|.*|, sub {                     #
        #                 &rex_error_not_found                            #
        #         }                                                       #
        # );                                                              #
        ###################################################################


	$self->rebuild_dispatch;
	$self->listen;
	$self->accept;

	$cv->recv();
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
	$sub->();		#run the configuration for the server
	$server;
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
		Log::OK::TRACE and log_info "Including server script from $path";
		try {
			eval "package $options{package} {
			unless (do \$path){

			log_error \$!;
			log_error \$@;

			}
			}";
		}
		#catch($e){
		catch {
			log_error $_;
			die "Could not include file $path";	
		};
	}
}

###################################
# sub usac_interface {            #
#         my $server=$_;          #
#         $server->[host_]=$_[0]; #
# }                               #
# sub usac_port {                 #
#         my $server=$_;          #
#         $server->[port_]=$_[0]; #
# }                               #
###################################
sub usac_listen {
	#specify a interface and port number	
	my $pairs=pop;	#Content is the last item
	my %options=@_;
	my $site=$options{parent}//$uSAC::HTTP::Site;
	$site->add_listener(%options, $pairs);
}

#TODO:
# We wany to either specifiy the interface name (ie eth0 wlan0 etc)
# or the specific address which exists on an interface.
# need to look at GETIFADDRS library/syscall;
#
sub add_listener {
	my $site=shift;
	my $pairs=pop;	#Content is the last item
	my %options=@_;

	my @uri;
	my $type=$options{type}//'tcp';
	#type can be
	# tcp
	# unix
	# quic
	
	#Do a check on the scheme type
	if(ref($pairs) eq "ARRAY"){
		@uri= map {
			URI->new("http://$_")}
		@$pairs;
			#push $site->[listen_]->@*, @$pairs;
	}
	else {
		
		@uri= map {URI->new("http://$_")} ($pairs);
		#push $site->[listen_]->@*, $pairs;
	}
	@uri=map {
			if(/localhost/){
				(
					URI->new("http://127.0.0.1:".$_->port),
					URI->new("http://[::1]:".$_->port)
				)
			}
			else {
				($_);
			}
		} @uri;
	unless($options{no_hosts}){
		push $site->host->@*, map {substr $_->opaque,2 } @uri;
	}
	for(@uri){
		die "Error parsing listener: $_ " unless ref;
	}
	say "HOsts: ", $site->host->@*;
	push $site->[listen_]->@*, @uri;
}

sub usac_workers {
	my $workers=pop;	#Content is the last item
	my %options=@_;
	my $site=$options{parent}//$uSAC::HTTP::Site;

	#FIXME
	$site->[workers_]=$workers;
}


sub usac_sub_product {
	my $sub_product=pop;	#Content is the last item
	my %options=@_;
	my $server=$options{parent}//$uSAC::HTTP::Site;
	$server->[static_headers_]=[
	HTTP_SERVER()=>(uSAC::HTTP::Server::NAME."/".uSAC::HTTP::Server::VERSION." ".join(" ", $sub_product) )];
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
