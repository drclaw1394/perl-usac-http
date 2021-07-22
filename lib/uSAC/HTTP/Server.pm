package uSAC::HTTP::Server; 
use common::sense;
use Data::Dumper;

use constant NAME=>"uSAC";
use constant VERSION=>"0.1";
#our @Subproducts=();		#Global to be provided by applcation

use version;our $VERSION = version->declare('v0.1');
use feature "refaliasing";
#use feature ":all";

#use uSAC::HTTP::Server::Kit;

#use Exporter;
#our @ISA = qw(Exporter);
#our @EXPORT_OK = our @EXPORT = qw(http_server);
#
use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK);


use AnyEvent;
use AnyEvent::Socket;
use AnyEvent::Handle;
use Scalar::Util 'refaddr', 'weaken';
use Errno qw(EAGAIN EINTR);
use AnyEvent::Util qw(WSAEWOULDBLOCK guard AF_INET6 fh_nonblocking);
use Socket qw(AF_INET AF_UNIX SOCK_STREAM SOCK_DGRAM SOL_SOCKET SO_REUSEADDR SO_REUSEPORT TCP_NODELAY IPPROTO_TCP TCP_NOPUSH TCP_NODELAY TCP_FASTOPEN);

#use Encode ();
#use Compress::Zlib ();
#use MIME::Base64 ();
use Time::HiRes qw/gettimeofday/;

use Carp 'croak';

use constant MAX_READ_SIZE => 128 * 1024;

#Class attribute keys
use enum (
	"host_=0",qw<port_ cb_ listen_ graceful_ aws_ fh_ fhs_ backlog_ read_size_ upgraders_ max_header_size_ sessions_ active_connections_ total_connections_ active_requests_ zombies_ seconds_timer_ www_roots_ total_requests_>
);

use uSAC::HTTP::Rex;
use uSAC::HTTP::Server::WS;
use uSAC::HTTP::Server::Session;
use uSAC::HTTP::v1_1;
use uSAC::HTTP::v1_1_Reader;

given(\%uSAC::HTTP::Server::Session::make_reader_reg){
	$_->{http1_1_base}=\&make_reader;
	$_->{http1_1_form_data}=\&make_form_data_reader;
	$_->{http1_1_urlencoded}=\&make_form_urlencoded_reader;
	#$_->{http1_1_default_writer}=\&make_default_writer;
	$_->{websocket}=\&make_websocket_reader;
}
given(\%uSAC::HTTP::Server::Session::make_writer_reg){
	$_->{http1_1_default_writer}=\&make_default_writer;
	$_->{websocket}=\&make_websocket_server_writer;
}

#Add a mechanism for sub classing
use constant KEY_OFFSET=>0;
use constant KEY_COUNT=>total_requests_-host_+1;


use constant LF => "\015\012";

#Server Global values
our $Date;	#For date header
our $DEFAULT_MIME=>"application/octet-stream";

#our $ERROR_PAGE=>
\our %MIME=do "./mime.pl";

sub new {
	my $pkg = shift;
	my $self = bless [], $pkg;
	my %options=@_;
	$self->[host_]=$options{host}//"0.0.0.0";
	$self->[port_]=$options{iport}//8080;
	$self->[cb_]=$options{cb}//sub { (200,"Change me")};
	$self->[zombies_]=[];
	$self->[backlog_]=4096;
	$self->[read_size_]=4096;
	$self->[max_header_size_]=MAX_READ_SIZE;
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

sub uSAC::HTTP::Server::destroyed::AUTOLOAD {}
sub destroy { %{ bless $_[0], 'uSAC::HTTP::Server::destroyed' } = (); }
sub DESTROY { $_[0]->destroy };



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

	state @months = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
	state @days= qw(Sun Mon Tue Wed Thu Fri Sat);

	$self->[seconds_timer_]=AE::timer 0,1, sub {
		my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) =gmtime;
		#export to globally available time?
		#
		#Format Tue, 15 Nov 1994 08:12:31 GMT
		$Date="$days[$wday], $mday $months[$mon] $year $hour:$min:$sec GMT";
	
		#say scalar $self->[zombies_]->@*;
		#say "Session count : ",scalar keys $self->[sessions_]->%*;
	};
}
#sub incoming;
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
		$self->[aws_]{ fileno $fl } = AE::io $fl, 0, sub {
			my $peer;
			$peer = accept my $fh, $fl;
				#while ($fl and ($peer = accept my $fh, $fl)) {

				
				fcntl $fh, F_SETFL, fcntl($fh, F_GETFL,0)|O_NONBLOCK;

				setsockopt $fh, 6, TCP_NODELAY, 1
					or Carp::croak "listen/so_nodelay $!"
						unless AnyEvent::WIN32; # work around windows bug
				#setsockopt $fh, IPPROTO_TCP, TCP_NOPUSH, 1 or die "error setting no push";

				#TODO: setup timeout for bad clients/connections

				$id = ++$seq;


				$session=pop @zombies;#@{$self->[zombies_]};
				if(defined $session){
					uSAC::HTTP::Server::Session::revive $session, $id, $fh;
				}
				else {
					$session=uSAC::HTTP::Server::Session::new(undef,$id,$fh,$self);

				}
				uSAC::HTTP::Server::Session::push_reader $session,"http1_1_base",undef; 
				$sessions{ $id } = $session;
				$active_connections++;
				$total_connections++;
		};
	}
	return;
}

sub noaccept {
	my $self = shift;
	delete $self->[aws_];
}

sub peer_info {
	my $fh = shift;
	#my ($port, $host) = AnyEvent::Socket::unpack_sockaddr getpeername($fh);
	#return AnyEvent::Socket::format_address($host).':'.$port;
}


sub req_wbuf_len {
	my $self = shift;
	my $req = shift;
	return undef unless exists $self->{ $req->headers->{INTERNAL_REQUEST_ID} };
	return 0 unless exists $self->{ $req->headers->{INTERNAL_REQUEST_ID} }{wbuf};
	return length ${ $self->{ $req->headers->{INTERNAL_REQUEST_ID} }{wbuf} };
}

sub badconn {
	my ($self,$fh,$rbuf,$msg) = @_;
	my $outbuf = (length $$rbuf > 2048) ?
		substr($$rbuf,0,2045).'...' :
		"$$rbuf";
	$outbuf =~ s{(\p{C}|\\)}{ sprintf "\\%03o", ord $1 }sge;
	my $remote = peer_info($fh);
	my $fileno = fileno $fh;
	warn "$msg from $remote (fd:$fileno) <$outbuf>\n";
}

#############################################################################################################################
# sub incoming {                                                                                                            #
#         state $seq=0;                                                                                                     #
#         weaken( my $self = shift );                                                                                       #
#         # warn "incoming @_";                                                                                             #
#         $self->[total_connections_]++;                                                                                    #
#         my ($fh,$rhost,$rport) = @_;                                                                                      #
#         my $id = ++$seq;#++$self->{seq}; #refaddr $fh;                                                                    #
#                                                                                                                           #
#         #my $timeout; $timeout=AE::timer 10,0, sub {say "TIMEOUT";$timeout=>undef;$self->drop($id)};                      #
#         #weaken $timeout;                                                                                                 #
#         my $r=uSAC::HTTP::Server::Session::new(undef,$id,$fh,$self);#makes network reader/writer                          #
#                                                                                                                           #
#         $self->[sessions_]{ $id } = $r;#bless $r, "uSAC::HTTP::Server::Session";                                          #
#         $self->[active_connections_]++;                                                                                   #
#                                                                                                                           #
#         #my $write= uSAC::HTTP::v1_1::make_writer $r, ; #$self->[sessions_]{$id};                                         #
#         #my $write;#= uSAC::HTTP::Server::Session::push_writer $r, \&uSAC::HTTP::v1_1::make_writer;                       #
#         uSAC::HTTP::Server::Session::push_reader $r, \&uSAC::HTTP::v1_1_Reader::make_reader;    #push protocol for reader #
#                                                                                                                           #
# }                                                                                                                         #
#############################################################################################################################

sub ws_close {
	my $self = shift;
	for (values %{ $self->{wss} }) {
		$_ && $_->close();
	}
	warn "$self->[active_requests_] / $self->[active_connections_]";
}

sub graceful {
	my $self = shift;
	my $cb = pop;
	delete $self->[aws_];
	close $_ for values %{ $self->[fhs_] };
	if ($self->[active_requests_] == 0 or $self->[active_connections_] == 0) {
		$cb->();
	} else {
		$self->[graceful_] = $cb;
		$self->ws_close();
	}
}


1; # End of uSAC::HTTP::Server
__END__

=head1 SYNOPSIS

    use uSAC::HTTP::Server;
    my $s = uSAC::HTTP::Server->new(
        host => '0.0.0.0',
        port => 80,
        cb => sub {
          my $request = shift;
          my $status  = 200;
          my $content = "<h1>Reply message</h1>";
          my $headers = { 'content-type' => 'text/html' };
          $request->reply($status, $content, headers => $headers);
        }
    );
    $s->listen;
    
    ## you may also prefork on N cores:
    
    # fork() ? next : last for (1..$N-1);
    
    ## Of course this is very simple example
    ## don't use such prefork in production
    
    $s->accept;
    
    my $sig = AE::signal INT => sub {
        warn "Stopping server";
        $s->graceful(sub {
            warn "Server stopped";
            EV::unloop;
        });
    };
    
    EV::loop;

=head1 DESCRIPTION

uSAC::HTTP::Server is a very fast asynchronous HTTP server written in perl. 
It has been tested in high load production environments and may be considered both fast and stable.

One can easily implement own HTTP daemon with uSAC::HTTP::Server and Daemond::Lite module,
both found at L<https://github.com/Mons>

This is a second verson available as AnyEvent-HTTP-Server-II. The first version is now obsolette.

=head1 HANDLING REQUEST

You can handle HTTP request by passing cb parameter to uSAC::HTTP::Server->new() like this:


  my $dispatcher = sub {
    my $request = shift;
    #... Request processing code goes here ...
    1;
  };

  my $s = uSAC::HTTP::Server->new( host => '0.0.0.0', port => 80, cb => $dispatcher,);

$dispatcher coderef will be called in a list context and it's return value should resolve 
to true, or request processing will be aborted by AnyEvent:HTTP::Server.

One able to process POST requests by returning specially crafted  hash reference from cb 
parameter coderef ($dispatcher in out example). This hash must contain the B<form> key, 
holding a code reference. If B<conetnt-encoding> header is 
B<application/x-www-form-urlencoded>, form callback will be called.

  my $post_action = sub {
    my ( $request, $form ) = @_;
    $request->reply(
      200, # HTTP Status
      "You just send long_data_param_name value of $form->{long_data_param_name}",  # Content
      headers=> { 'content-type' =< 'text/plain'}, # Response headers
    );
  }

  my $dispatcher = sub {
    my $request = shift;

    if ( $request->headers->{'content-type'} =~ m{^application/x-www-form-urlencoded\s*$} ) {
      return {
        form => sub {
          $cb->( $request, $post_action);
        },
      };
    } else {
      # GET request processing
    } 

  };

  my $s = uSAC::HTTP::Server->new( host => '0.0.0.0', port => 80, cb => $dispatcher,);

=head1 EXPORT

  Does not export anything

=head1 SUBROUTINES/METHODS

=head2 new - create HTTP Server object

  Arguments to constractor should be passed as a key=>value list, for example

    my $s = uSAC::HTTP::Server->new(
        host => '0.0.0.0',
        port => 80,
        cb   => sub {
            my $req = shift;
            return sub {
                my ($is_last, $bodypart) = @_;
                $r->reply(200, "<h1>Reply message</h1>", headers => { 'content-type' => 'text/html' });
            }
        }
    );


=head3 host 

  Specify interfaces to bind a listening socket to
  Example: host => '127.0.0.1'
    
=head3 port

  Listen on this port
  Example: port => 80

=head3 cb

  This coderef will be called on incoming request
  Example: cb => sub {
    my $request = shift;
    my $status  = 200;
    my $content = "<h1>Reply message</h1>";
    my $headers = { 'content-type' => 'text/html' };
    $request->reply($status, $content, headers => $headers);
  }

  The first argument to callback will be request object (uSAC::HTTP::Server::Req).

=head2 listen - bind server socket to host and port, start listening for connections

  This method has no arguments.

  This method is commonly called from master process before it forks.

  Errors in host and port may result in exceptions, so you probably want to eval this call.

=head2 accept - start accepting connections

  This method has no arguments.

  This method is commonly called in forked children, which serve incoming requests.

=head2 noaccept - stop accepting connections (while still listening on a socket)

  This method has no arguments.

=head2 graceful - Stop accepting new connections and gracefully shut down the server

  Wait until all connections will be handled and execute supplied coderef after that.
  This method can be useful in signal handlers.


=head1 RESOURCES

=over 4

=item * GitHub repository

L<http://github.com/Mons/AnyEvent-HTTP-Server-II>

=back

=head1 ACKNOWLEDGEMENTS

=over 4

=item * Thanks to B<Marc Lehmann> for L<AnyEvent>

=item * Thanks to B<Robin Redeker> for L<uSAC::HTTPD>

=back

=head1 AUTHOR

Mons Anderson, <mons@cpan.org>

=head1 LICENSE

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

=cut
