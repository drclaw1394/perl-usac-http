package uSAC::HTTP::Server; 
use common::sense;
use Data::Dumper;
use IO::Handle;
use constant NAME=>"uSAC";
use constant VERSION=>"0.1";
our @Subproducts;#=();		#Global to be provided by applcation

use version;our $VERSION = version->declare('v0.1');
use feature "refaliasing";

use uSAC::HTTP;			#site, sub site, and host
use Hustle::Table;		#dispatching of endpoints
use uSAC::HTTP::Rex;		#subs for replying

use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK);


use AnyEvent;
use AnyEvent::Socket;
use AnyEvent::Handle;
use Scalar::Util 'refaddr', 'weaken';
use Errno qw(EAGAIN EINTR);
use AnyEvent::Util qw(WSAEWOULDBLOCK guard AF_INET6 fh_nonblocking);
use Socket qw(AF_INET AF_UNIX SOCK_STREAM SOCK_DGRAM SOL_SOCKET SO_REUSEADDR SO_REUSEPORT TCP_NODELAY IPPROTO_TCP TCP_NOPUSH TCP_NODELAY TCP_FASTOPEN SO_LINGER);

use Time::HiRes qw/gettimeofday/;

use Carp 'croak';

#use constant MAX_READ_SIZE => 128 * 1024;

#Class attribute keys
#max_header_size_
use enum (
	"host_=0",qw<port_ enable_hosts_ sites_ table_ cb_ listen_ graceful_ aws_ fh_ fhs_ backlog_ read_size_ upgraders_ sessions_ active_connections_ total_connections_ active_requests_ zombies_ stream_timer_ server_clock_ www_roots_ total_requests_>
);


use uSAC::HTTP;
use uSAC::HTTP::Code ":constants";
use uSAC::HTTP::Header ":constants";
use uSAC::HTTP::Session;
use uSAC::HTTP::v1_1;
use uSAC::HTTP::v1_1_Reader;

use constant STATIC_HEADERS=>
HTTP_SERVER.": ".uSAC::HTTP::Server::NAME."/".uSAC::HTTP::Server::VERSION." ".join(" ", @uSAC::HTTP::Server::Subproducts).LF ;

given(\%uSAC::HTTP::Session::make_reader_reg){
        $_->{http1_1_base}=\&make_reader;
        $_->{http1_1_form_data}=\&make_form_data_reader;
        $_->{http1_1_urlencoded}=\&make_form_urlencoded_reader;
        #$_->{http1_1_default_writer}=\&make_default_writer;
        $_->{websocket}=\&make_websocket_reader;
}

given(\%uSAC::HTTP::Session::make_writer_reg){
        $_->{http1_1_default_writer}=\&make_default_writer;
        $_->{http1_1_socket_writer}=\&make_socket_writer;
        $_->{websocket}=\&make_websocket_server_writer;
}

#Add a mechanism for sub classing
use constant KEY_OFFSET=>0;
use constant KEY_COUNT=>total_requests_-host_+1;


#use constant LF => "\015\012";

#Server Global values
#our $Date;	#For date header
our $DEFAULT_MIME=>"application/octet-stream";

#our $ERROR_PAGE=>
\our %MIME=do "./mime.pl";


# Basic handlers
#
# Welcome message
sub usac_welcome {
	state $data;
	say " WELCOME";
	unless($data){
		local $/=undef;
		$data=<DATA>;
	}
	state $sub=sub {
		rex_reply_simple @_, HTTP_OK, undef, $data;
		return; #Enable caching
	}
}

sub usac_default_handler {
		#my ($line,$rex)=@_;
		state $sub=sub {
			rex_reply_simple @_, HTTP_NOT_FOUND,undef,"Not found";
			return;
		}
}

sub new {
	my $pkg = shift;
	my $self = bless [], $pkg;
	my %options=@_;
	$self->[host_]=$options{host}//"0.0.0.0";
	$self->[port_]=$options{port}//8080;
	$self->[enable_hosts_]=$options{enable_hosts};
	$self->[table_]=Hustle::Table->new(usac_default_handler);
	$self->[cb_]=$options{cb}//sub { (200,"Change me")};
	$self->[zombies_]=[];
	register_site($self, uSAC::HTTP->new(id=>"default"));
	$self->[backlog_]=4096;
	$self->[read_size_]=4096;
	#$self->[max_header_size_]=MAX_READ_SIZE;
	$self->[sessions_]={};
	$self->[upgraders_]= {
			"websocket" =>\&uSAC::HTTP::Server::WS::upgrader
		};
		
	
	if (exists $self->[listen_]) {
		$self->[listen_] = [ $self->[listen_] ] unless ref $self->[listen_];
		my %dup;
		for (@{ $self->[listen_] }) {
			if($dup{ lc $_ }++) {
				croak "Duplicate host $_ in listen\n";
			}
			my ($h,$p) = split ':',$_,2;
			$h = '0.0.0.0' if $h eq '*';
			$h = length ( $self->[host_] ) ? $self->[host_] : '0.0.0.0' unless length $h;
			$p = length ( $self->[port_] ) ? $self->[port_] : 8080 unless length $p;
			$_ = join ':',$h,$p;
		}
		($self->[host_],$self->[port_]) = split ':',$self->[listen_][0],2;
	} else {
		$self->[listen_] = [ join(':',$self->[host_],$self->[port_]) ];
	}

	$self->can("handle_request")
		and croak "It's a new version of ".__PACKAGE__.". For old version use `legacy' branch, or better make some minor patches to support new version";
	
	#$self->{request} = 'uSAC::HTTP::Rex';
	
	return $self;
}


sub listen {
	my $self = shift;
	for my $listen (@{ $self->[listen_] }) {
		my ($host,$service) = split ':',$listen,2;
		$service = $self->[port_] unless length $service;
		$host = $self->[host_] unless length $host;
		$host = $AnyEvent::PROTOCOL{ipv4} < $AnyEvent::PROTOCOL{ipv6} && AF_INET6 ? "::" : "0" unless length $host;
		
		my $ipn = parse_address $host
			or Carp::croak "$self.listen: cannot parse '$host' as host address";
		
		my $af = address_family $ipn;
		
		# win32 perl is too stupid to get this right :/
		Carp::croak "listen/socket: address family not supported"
			if AnyEvent::WIN32 && $af == AF_UNIX;
		
		socket my $fh, $af, SOCK_STREAM, 0 or Carp::croak "listen/socket: $!";
		
		say "FILENO ",fileno $fh;
		if ($af == AF_INET || $af == AF_INET6) {
			setsockopt $fh, SOL_SOCKET, SO_REUSEADDR, 1
				or Carp::croak "listen/so_reuseaddr: $!"
					unless AnyEvent::WIN32; # work around windows bug

			setsockopt $fh, SOL_SOCKET, SO_REUSEPORT, 1
				or Carp::croak "listen/so_reuseport: $!"
					unless AnyEvent::WIN32; # work around windows bug

			setsockopt $fh, 6, TCP_NODELAY, 1
				or Carp::croak "listen/so_nodelay $!"
					unless AnyEvent::WIN32; # work around windows bug
			
			unless ($service =~ /^\d*$/) {
				$service = (getservbyname $service, "tcp")[2]
					or Carp::croak "tcp_listen: $service: service unknown"
			}
		} elsif ($af == AF_UNIX) {
			unlink $service;
		}
		
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
	my $timeout=10;
	$self->[server_clock_]=time;	

	$self->[stream_timer_]=AE::timer 0,$interval, sub {
		#iterate through all connections and check the difference between the last update
		$self->[server_clock_]+=$interval;
		#and the current tick
		my $session;
		for(keys $self->[sessions_]->%*){
			$session=$self->[sessions_]{$_};
			#say "checking id: $_ time: ", $session->[uSAC::HTTP::Session::time_];

			if(($self->[server_clock_]-$session->[uSAC::HTTP::Session::time_])> $timeout){
				$session->[uSAC::HTTP::Session::closeme_]=1;
				$session->[uSAC::HTTP::Session::dropper_]->();
			}
		}
	};

        ###########################################################################################
        #                                                                                         #
        # state @months = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);                    #
        # state @days= qw(Sun Mon Tue Wed Thu Fri Sat);                                           #
        #                                                                                         #
        # $self->[seconds_timer_]=AE::timer 0,1, sub {                                            #
        #         my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) =gmtime;               #
        #         #export to globally available time?                                             #
        #         #                                                                               #
        #         #Format Tue, 15 Nov 1994 08:12:31 GMT                                           #
        #         $Date="$days[$wday], $mday $months[$mon] ".($year+1900)." $hour:$min:$sec GMT"; #
        #         #say scalar $self->[zombies_]->@*;                                              #
        #         #say "Session count : ",scalar keys $self->[sessions_]->%*;                     #
        # };                                                                                      #
        ###########################################################################################
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
	#say length $packed_address;

	#say "Listed fd ", fileno($fh);
	sub {
		my $handle;
		my $result=syscall $syscall_number, $fn, $packed_address, $i;
		if($result<0){
			#say "Syscall error: $result: $!";
		}
		else {
			#say "syscal ok";
			#open from fd
			$handle=IO::Handle->new_from_fd($result ,"<");
			#open $handle, "<&=$result";
		}
		return $handle;
	}

}

sub accept {
	state $seq=0;
	weaken( my $self = shift );
	\my @zombies=$self->[zombies_];
	\my %sessions=$self->[sessions_];
	\my $active_connections=\$self->[active_connections_];
	\my $total_connections=\$self->[total_connections_];
	my $session;
	my $id;
	for my $fl ( values %{ $self->[fhs_] }) {
		#my $accept=make_sysaccept $fl;
		$self->[aws_]{ fileno $fl } = AE::io $fl, 0, sub {
			my $peer;
			while(($peer = accept my $fh, $fl)){
			#(while(my $fh=sysaccept($fl)){
			#while(my $fh=$accept->()){
				last unless $fh;
				#while ($fl and ($peer = accept my $fh, $fl)) {

				binmode	$fh, ":raw";
				#fcntl $fh, F_SETFL, fcntl($fh, F_GETFL,0)|O_NONBLOCK;
				fcntl $fh, F_SETFL,O_NONBLOCK;

				#TODO:
				# Need to do OS check here
				setsockopt $fh, IPPROTO_TCP, TCP_NODELAY, 1 or Carp::croak "listen/so_nodelay $!";
				#setsockopt $fh, IPPROTO_TCP, TCP_NOPUSH, 1 or die "error setting no push";

				#TODO: setup timeout for bad clients/connections

				#setsockopt($fh, SOL_SOCKET, SO_LINGER, pack ("ll",1,0));
				$id = ++$seq;


				$session=pop @zombies;
				if($session){
					uSAC::HTTP::Session::revive $session, $id, $fh;
					uSAC::HTTP::Session::push_writer 
						$session,
						"http1_1_socket_writer",
						undef;
				}
				else {
					$session=uSAC::HTTP::Session::new(undef,$id,$fh,$self->[sessions_],$self->[zombies_],$self);
					#TODO: push correct writer ie, ssl  for other sessions
					uSAC::HTTP::Session::push_writer 
						$session,
						"http1_1_socket_writer",
						undef;
				}

				uSAC::HTTP::Session::push_reader $session,"http1_1_base",undef; 
				#initiate read
				uSAC::HTTP::Session::_make_reader $session;
				$sessions{ $id } = $session;
				$active_connections++;
				$total_connections++;
			}
		};
	}
	return;
}

sub current_cb {
	shift->[cb_];
}
sub enable_hosts {
	shift->[enable_hosts_];
}
sub add_end_point{
	my ($self,$matcher,$end)=@_;
	$self->[table_]->add($matcher,$end);
}

#registers a site object with the server
#returns the object
sub register_site {
	my $self=shift;
	my $site=shift;
	$site->[uSAC::HTTP::server_]=$self;
	my $name=$site->[uSAC::HTTP::id_];
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
sub route {
	my $self=shift;
	$self->site->route(@_);
}

sub rebuild_dispatch {
	my $self=shift;
	my $cache={};
	keys %$cache=512;
	#check if the default site has more than one( ie the default) entry
	#if 0, then add the server catch all
	#else do not modifiy
	if($self->[table_]->@*==1 or keys $self->[sites_]->%* > 1){
		site_route $self=>'GET'=>qr{.*}=>()=>usac_welcome;
	}


	$self->[cb_]=$self->[table_]->prepare_dispatcher(type=>"online", cache=>$cache);
}

sub run {
	my $self=shift;
	my $cv=AE::cv;
	$self->rebuild_dispatch;
	$self->listen;
	$self->accept;

	$cv->recv();
}



#########################################################################################
# sub peer_info {                                                                       #
#         my $fh = shift;                                                               #
#         #my ($port, $host) = AnyEvent::Socket::unpack_sockaddr getpeername($fh);      #
#         #return AnyEvent::Socket::format_address($host).':'.$port;                    #
# }                                                                                     #
#                                                                                       #
#                                                                                       #
# sub req_wbuf_len {                                                                    #
#         my $self = shift;                                                             #
#         my $req = shift;                                                              #
#         return undef unless exists $self->{ $req->headers->{INTERNAL_REQUEST_ID} };   #
#         return 0 unless exists $self->{ $req->headers->{INTERNAL_REQUEST_ID} }{wbuf}; #
#         return length ${ $self->{ $req->headers->{INTERNAL_REQUEST_ID} }{wbuf} };     #
# }                                                                                     #
#                                                                                       #
# sub badconn {                                                                         #
#         my ($self,$fh,$rbuf,$msg) = @_;                                               #
#         my $outbuf = (length $$rbuf > 2048) ?                                         #
#                 substr($$rbuf,0,2045).'...' :                                         #
#                 "$$rbuf";                                                             #
#         $outbuf =~ s{(\p{C}|\\)}{ sprintf "\\%03o", ord $1 }sge;                      #
#         my $remote = peer_info($fh);                                                  #
#         my $fileno = fileno $fh;                                                      #
#         warn "$msg from $remote (fd:$fileno) <$outbuf>\n";                            #
# }                                                                                     #
#                                                                                       #
#                                                                                       #
# sub ws_close {                                                                        #
#         my $self = shift;                                                             #
#         for (values %{ $self->{wss} }) {                                              #
#                 $_ && $_->close();                                                    #
#         }                                                                             #
#         warn "$self->[active_requests_] / $self->[active_connections_]";              #
# }                                                                                     #
#                                                                                       #
# sub graceful {                                                                        #
#         my $self = shift;                                                             #
#         my $cb = pop;                                                                 #
#         delete $self->[aws_];                                                         #
#         close $_ for values %{ $self->[fhs_] };                                       #
#         if ($self->[active_requests_] == 0 or $self->[active_connections_] == 0) {    #
#                 $cb->();                                                              #
#         } else {                                                                      #
#                 $self->[graceful_] = $cb;                                             #
#                 $self->ws_close();                                                    #
#         }                                                                             #
# }                                                                                     #
#                                                                                       #
#########################################################################################

1; 
__DATA__
<html>
	<body>
		Welcome to uSAC
	</body>
</html>
