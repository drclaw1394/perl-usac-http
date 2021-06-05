package AnyEvent::HTTP::Server;
use common::sense;
=head1 NAME

AnyEvent::HTTP::Server - AnyEvent HTTP/1.1 Server

=cut

use version;our $VERSION = version->declare('v0.1');
use feature "refaliasing";
#use feature ":all";

#use AnyEvent::HTTP::Server::Kit;

#use Exporter;
#our @ISA = qw(Exporter);
#our @EXPORT_OK = our @EXPORT = qw(http_server);

use AnyEvent;
use AnyEvent::Socket;
use AnyEvent::Handle;
use Scalar::Util 'refaddr', 'weaken';
use Errno qw(EAGAIN EINTR);
use AnyEvent::Util qw(WSAEWOULDBLOCK guard AF_INET6 fh_nonblocking);
use Socket qw(AF_INET AF_UNIX SOCK_STREAM SOCK_DGRAM SOL_SOCKET SO_REUSEADDR IPPROTO_TCP TCP_NODELAY);

#use Encode ();
#use Compress::Zlib ();
#use MIME::Base64 ();
use Time::HiRes qw/gettimeofday/;

use Carp 'croak';

use AnyEvent::HTTP::Server::Req;

#Class attribute keys
use enum (
	"host_=0",qw<port_ cb_ listen_ fh_ backlog_ read_size_ max_header_size_ active_connections_ total_connections_ active_requests_ total_requests_>
);

#Add a mechanism for sub classing
use constant KEY_OFFSET=>0;
use constant KEY_COUNT=>total_requests_-host_+1;

our $MIME;
use constant MAX_READ_SIZE => 128 * 1024;
sub DEBUG () { 0 }

our $LF = "\015\012";


sub new {
	my $pkg = shift;
	my $self = bless {
		backlog   => 1024,
		read_size => 4096,
		max_header_size => MAX_READ_SIZE,
		@_,
		active_connections => 0,
		total_connections => 0,
		active_requests => 0,
		total_requests => 0,
	}, $pkg;
	
	if (exists $self->{listen}) {
		$self->{listen} = [ $self->{listen} ] unless ref $self->{listen};
		my %dup;
		for (@{ $self->{listen} }) {
			if($dup{ lc $_ }++) {
				croak "Duplicate host $_ in listen\n";
			}
			my ($h,$p) = split ':',$_,2;
			$h = '0.0.0.0' if $h eq '*';
			$h = length ( $self->{host} ) ? $self->{host} : '0.0.0.0' unless length $h;
			$p = length ( $self->{port} ) ? $self->{port} : 8080 unless length $p;
			$_ = join ':',$h,$p;
		}
		($self->{host},$self->{port}) = split ':',$self->{listen}[0],2;
	} else {
		$self->{listen} = [ join(':',$self->{host},$self->{port}) ];
	}

	$self->can("handle_request")
		and croak "It's a new version of ".__PACKAGE__.". For old version use `legacy' branch, or better make some minor patches to support new version";
	
	$self->{request} = 'AnyEvent::HTTP::Server::Req';
	
	return $self;
}

sub AnyEvent::HTTP::Server::destroyed::AUTOLOAD {}
sub destroy { %{ bless $_[0], 'AnyEvent::HTTP::Server::destroyed' } = (); }
sub DESTROY { $_[0]->destroy };



sub listen {
	my $self = shift;
		
	for my $listen (@{ $self->{listen} }) {
		my ($host,$service) = split ':',$listen,2;
		$service = $self->{port} unless length $service;
		$host = $self->{host} unless length $host;
		$host = $AnyEvent::PROTOCOL{ipv4} < $AnyEvent::PROTOCOL{ipv6} && AF_INET6 ? "::" : "0" unless length $host;
		
		my $ipn = parse_address $host
			or Carp::croak "$self.listen: cannot parse '$host' as host address";
		
		my $af = address_family $ipn;
		
		# win32 perl is too stupid to get this right :/
		Carp::croak "listen/socket: address family not supported"
			if AnyEvent::WIN32 && $af == AF_UNIX;
		
		socket my $fh, $af, SOCK_STREAM, 0 or Carp::croak "listen/socket: $!";
		
		if ($af == AF_INET || $af == AF_INET6) {
			setsockopt $fh, SOL_SOCKET, SO_REUSEADDR, 1
				or Carp::croak "listen/so_reuseaddr: $!"
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
	
		$self->{fh} ||= $fh; # compat
		$self->{fhs}{fileno $fh} = $fh;
	}
	
	$self->prepare();
	
	for ( values  %{ $self->{fhs} } ) {
		listen $_, $self->{backlog}
			or Carp::croak "listen/listen on ".(fileno $_).": $!";
	}
	
	return wantarray ? do {
		#my ($service, $host) = AnyEvent::Socket::unpack_sockaddr( getsockname $self->{fh} );
		#(format_address $host, $service);
		();
	} : ();
}

sub prepare {}
sub incoming;
sub accept {
	weaken( my $self = shift );
	for my $fl ( values %{ $self->{fhs} }) {
		$self->{aws}{ fileno $fl } = AE::io $fl, 0, sub {
			while ($fl and (my $peer = accept my $fh, $fl)) {
				AnyEvent::Util::fh_nonblocking $fh, 1; # POSIX requires inheritance, the outside world does not
				#$self->incoming($fh);
				incoming $self,$fh;

                                ####################################################################################
                                # if ($self->{want_peer}) {                                                        #
                                #         #my ($service, $host) = AnyEvent::Socket::unpack_sockaddr $peer;         #
                                #         #$self->incoming($fh, AnyEvent::Socket::format_address $host, $service); #
                                # } else {                                                                         #
                                #         $self->incoming($fh);                                                    #
                                # }                                                                                #
                                ####################################################################################
			}
		};
	}
	return;
}

sub noaccept {
	my $self = shift;
	delete $self->{aws};
}

sub peer_info {
	my $fh = shift;
	#my ($port, $host) = AnyEvent::Socket::unpack_sockaddr getpeername($fh);
	#return AnyEvent::Socket::format_address($host).':'.$port;
}

sub drop {
	my ($self,$id,$err) = @_;
	$err =~ s/\015//sg;
	if ($err and $self->{debug_drop}) {
		my $fh = $self->{$id}{fh};
		my $remote = $fh && peer_info($fh);
		warn "Dropping connection $id from $remote: $err  (by @{[ (caller)[1,2] ]})\n";
	}
	my $r = delete $self->{$id};
	$self->{active_connections}--;
	%{ $r } = () if $r;
	
	( delete $self->{graceful} )->()
		if $self->{graceful} and $self->{active_requests} == 0;
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

sub incoming {
	weaken( my $self = shift );
	# warn "incoming @_";
	$self->{total_connections}++;
	my ($fh,$rhost,$rport) = @_;
	my $id = ++$self->{seq}; #refaddr $fh;


	my %r = ( fh => $fh, id => $id );
	my $buf;

	$self->{ $id } = \%r;
	$self->{active_connections}++;

        #######################################################################################################################################################################################
        # warn sprintf("Accepted connection $id (fd:%s) from %s ($self->{active_connections}/$self->{total_connections}; $self->{active_requests}/$self->{total_requests})\n", fileno($_[0]), #
        #         $self->{want_peer} ? "$_[1]:$_[2]" : peer_info($_[0])                                                                                                                       #
        # ) if $self->{debug_conn};                                                                                                                                                           #
        #######################################################################################################################################################################################

	my $write = sub {
		$self and exists $self->{$id} or return;
		my $ido=$self->{$id};
		\my $buf=\$_[0];

		if ( $ido->{wbuf} ) {
			$ido->{closeme} and return warn "Write ($buf) called while connection close was enqueued at @{[ (caller)[1,2] ]}";
			${ $ido->{wbuf} } .= defined $buf ? $buf : return $ido->{closeme} = 1;
			return;
		}
		elsif ( !defined $buf ) { return $self->drop($id); }

		$ido->{fh} or return do {
			warn "Lost filehandle while trying to send ".length($buf)." data for $id";
			$self->drop($id,"No filehandle");
			();
		};
		my $w = syswrite( $ido->{fh}, $buf );
		if ($w == length $buf) {
			# ok;
			if( $ido->{closeme} ) { $self->drop($id); };
		}
		elsif (defined $w) {
			#substr($buf,0,$w,'');
			$ido->{wbuf} = substr($buf,0,$w,'');
			#$buf;
			$ido->{ww} = AE::io $ido->{fh}, 1, sub {
				warn "ww.io.$id" if DEBUG;
				$self and $ido or return;
				$w = syswrite( $ido->{fh}, ${ $ido->{wbuf} } );
				if ($w == length ${ $ido->{wbuf} }) {
					delete $ido->{wbuf};
					delete $ido->{ww};
					if( $ido->{closeme} ) { $self->drop($id); }
				}
				elsif (defined $w) {
					${ $ido->{wbuf} } = substr( ${ $ido->{wbuf} }, $w );
					#substr( ${ $ido->{wbuf} }, 0, $w, '');
				}
				else { return $self->drop($id, "$!"); }
			};
		}
		else { return $self->drop($id, "$!"); }
	};

	my ($state,$seq) = (0,0);
	my ($method,$uri,$version,$lastkey,$contstate,$bpos,$len,$pos, $req);

	my $ixx = 0;
	my %h = ( INTERNAL_REQUEST_ID => $id, defined $rhost ? ( Remote => $rhost, RemotePort => $rport ) : () );
	$r{rw} = AE::io $fh, 0, sub {
		# warn "rw.io.$id (".(fileno $fh).") seq:$seq (ok:".($self ? 1:0).':'.(( $self && exists $self->{$id}) ? 1 : 0).")";# if DEBUG;
		$self and exists $self->{$id} or return;
		my ($pos0,$pos1,$pos2,$pos3);
		$len = sysread( $fh, $buf, MAX_READ_SIZE-length $buf, length $buf );
		while ( $self and $len ) {
			# warn "rw.io.$id.rd $len ($state)";
			if ($state == 0) {
				$method=substr($buf, $ixx, ($pos1=index($buf, " ", $ixx))-$ixx);
				$uri=substr($buf, ++$pos1, ($pos2=index($buf, " ", $pos1))-$pos1);
				$version=substr($buf, ++$pos2, ($pos3=index($buf, "\015\012", $pos2))-$pos2);
				if($pos3>=0){
					#end of line found
						$state   = 1;
						$lastkey = undef;
						++$seq;
						$self->{$id}{closeme}=1 if $version ne "1.1";
						warn "Received request N.$seq over ".fileno($fh).": $method $uri" if DEBUG;
						$self->{active_requests}++;
						#push @{ $r{req} }, [{}];
						$pos=$pos3+2;
						redo;
				}
				else {
					#need more. wait for event
					#Don't update $pos
				}
			}
			# warn "rw.io.$id.rd $len ($state) -> $pos";
			elsif ($state == 1) {
				# headers
				pos($buf) = $pos;
				warn "Parsing headers from pos $pos:".substr($buf,$pos) if DEBUG;
				while () {
					#warn "parse line >'".substr( $buf,pos($buf),index( $buf, "\012", pos($buf) )-pos($buf) )."'";
					if( $buf =~ /\G ([^:\000-\037\040]++)[\011\040]*+:[\011\040]*+ ([^\012\015;]*+(;)?[^\012\015]*+) \015?\012/sxogc ){
						$lastkey = lc $1;
						$h{ $lastkey } = exists $h{ $lastkey } ? $h{ $lastkey }.','.$2: $2;
						#warn "Captured header $lastkey = '$2'";
						if ( defined $3 ) {
							pos(my $v = $2) = $-[3] - $-[2];
							#warn "scan ';'";
							$h{ $lastkey . '+' . lc($1) } = ( defined $2 ? do { my $x = $2; $x =~ s{\\(.)}{$1}gs; $x } : $3 )
							while ( $v =~ m{ \G ; \s* ([^\s=]++)\s*= (?: "((?:[^\\"]++|\\.){0,4096}+)" | ([^;,\s]++) ) \s* }gcxso ); # "
							$contstate = 1;
						} else {
							$contstate = 0;
						}
					}
					elsif ($buf =~ /\G[\011\040]+/sxogc) { # continuation
						#warn "Continuation";
						if (length $lastkey) {
							$buf =~ /\G ([^\015\012;]*+(;)?[^\015\012]*+) \015?\012/sxogc or return pos($buf) = $bpos; # need more data;
							$h{ $lastkey } .= ' '.$1;
							if ( ( defined $2 or $contstate ) ) {
								#warn "With ;";
								if ( ( my $ext = index( $h{ $lastkey }, ';', rindex( $h{ $lastkey }, ',' ) + 1) ) > -1 ) {
									# Composite field. Need to reparse last field value (from ; after last ,)
									# full key rescan, because of possible case: <key:value; field="value\n\tvalue continuation"\n>
									# regexp needed to set \G
									pos($h{ $lastkey }) = $ext;
									#warn "Rescan from $ext";
									#warn("<$1><$2><$3>"),
									$h{ $lastkey . '+' . lc($1) } = ( defined $2 ? do { my $x = $2; $x =~ s{\\(.)}{$1}gs; $x } : $3 )
									while ( $h{ $lastkey } =~ m{ \G ; \s* ([^\s=]++)\s*= (?: "((?:[^\\"]++|\\.){0,4096}+)" | ([^;,\s]++) ) \s* }gcxso ); # "
									$contstate = 1;
								}
							}
						}
					}
					elsif ($buf =~ /\G\015?\012/sxogc) {
						#warn "Last line";
						last;
					}
					elsif($buf =~ /\G [^\012]* \Z/sxogc) {
						if (length($buf) - $ixx > $self->{max_header_size}) {
							$self->badconn($fh,\substr($buf, pos($buf), $ixx), "Header overflow at offset ".$pos."+".(length($buf)-$pos));
							return $self->drop($id, "Too big headers from $rhost for request <".substr($buf, $ixx, 32)."...>");
						}
						#warn "Need more";
						return pos($buf) = $bpos; # need more data
					}
					else {
						my ($line) = $buf =~ /\G([^\015\012]++)(?:\015?\012|\Z)/sxogc;
						$self->{active_requests}--;
						$self->badconn($fh,\$line, "Bad header for <$method $uri>+{@{[ %h ]}}");
						my $content = 'Bad request headers';
						my $str = "HTTP/1.1 400 Bad Request${LF}Connection:close${LF}Content-Type:text/plain${LF}Content-Length:".length($content)."${LF}${LF}".$content;
						$write->($str);
						$write->(undef);
						return;
					}
				}
				#Done with headers. 
				#
				#warn Dumper \%h;
				$pos = pos($buf);

				$self->{total_requests}++;

				#warn "Create request object";
				#$req = AnyEvent::HTTP::Server::Req->new(
				#	method  => $method,
				#	uri     => $uri,
				#	headers => \%h,
				#	write   => $write,
				#	guard   => guard { $self->{active_requests}--; },
				#);
				#my @rv = $self->{cb}->( $req );

				my @rv = $self->{cb}->( $req = bless [ $method, $uri, \%h, $write, undef,undef,undef, \$self->{active_requests}, $self, scalar gettimeofday() ], 'AnyEvent::HTTP::Server::Req' );
				weaken( $req->[8] );
				#my @rv = $self->{cb}->( $req = bless [ $method, $uri, \%h, $write ], 'AnyEvent::HTTP::Server::Req' );
				if (@rv) {
					if (ref $rv[0] eq 'CODE') {
						#print "CODE \n";
						$r{on_body} = $rv[0];
					}
					elsif ( ref $rv[0] eq 'HASH' ) {
						if ( $h{'content-type'}  =~ m{^
								multipart/form-data\s*;\s*
								boundary\s*=\s*
								(?:
								"((?:[^\\"]++|\\.){0,4096})" # " quoted entry
								|
								([^;,\s]+)
								)
								$}xsio and exists $rv[0]{multipart}
						) {

							my $bnd = '--'.( defined $1 ? do { my $x = $1; $x =~ s{\\(.)}{$1}gs; $x } : $2 );
							my $body = '';
							#warn "reading multipart with boundary '$bnd'";
							#warn "set on_body";
							my $cb = $rv[0]{multipart};
							$r{on_body} = sub {
								my ($last,$part) = @_;
								if ( length($body) + length($$part) > $self->{max_body_size} ) {
									# TODO;
								}
								$body .= $$part;
								#warn "Checking body '".$body."'";
								my $idx = index( $body, $bnd );
								while ( $idx > -1 and (
										( $idx + length($bnd) + 1 <= length($body) and substr($body,$idx+length($bnd),1) eq "\012" )
											or
										( $idx + length($bnd) + 2 <= length($body) and substr($body,$idx+length($bnd),2) eq "\015\012" )
											or
										( $idx + length($bnd) + 2 <= length($body) and substr($body,$idx+length($bnd),2) eq "\055\055" )
									) ) {
									#warn "have part";
									my $part = substr($body,$idx-2,1) eq "\015" ? substr($body,0,$idx-2) : substr($body,0,$idx-1);
									#warn Dumper $part;
									#substr($part, 0, ( substr($part,0,1) eq "\015" ) ? 2 : 1,'');
									#warn "captured $idx: '$part'";
									$body = substr($body,$idx + length $bnd);
									substr($body,0, ( substr($body,0,1) eq "\015" ) ? 2 : 1 ,'');
									#warn "body = '$body'";
									$idx = index( $body, $bnd );
									#warn "next part idx: $idx";
									length $part or next;
									#warn "Process part '$part'";

									my %hd;
									my $lk;
									while() {
										if( $part =~ /\G ([^:\000-\037\040]++)[\011\040]*+:[\011\040]*+ ([^\012\015;]++(;)?[^\012\015]*+) \015?\012/sxogc ){
											$lk = lc $1;
											$hd{ $lk } = exists $hd{ $lk } ? $hd{ $lk }.','.$2 : $2;
											if ( defined $3 ) {
												pos(my $v = $2) = $-[3] - $-[2];
												# TODO: testme
												$hd{ $lk . '+' . lc($1) } = ( defined $2 ? do { my $x = $2; $x =~ s{\\(.)}{$1}gs; $x } : $3 )
												while ( $v =~ m{ \G ; \s* ([^\s=]++)\s*= (?: "((?:[^\\"]++|\\.){0,4096}+)" | ([^;,\s]++) ) \s* }gcxso ); # "
											}
										}
										elsif ($part =~ /\G[\011\040]+/sxogc and length $lk) { # continuation
											$part =~ /\G([^\015\012]+)\015?\012/sxogc or next;
											$hd{ $lk } .= ' '.$1;
											if ( ( my $ext = index( $hd{ $lk }, ';', rindex( $hd{ $lk }, ',' ) + 1) ) > -1 ) {
												# Composite field. Need to reparse last field value (from ; after last ,)
												pos($hd{ $lk }) = $ext;
												$hd{ $lk . '+' . lc($1) } = ( defined $2 ? do { my $x = $2; $x =~ s{\\(.)}{$1}gs; $x } : $3 )
												while ( $hd{ $lk } =~ m{ \G ; \s* ([^\s=]++)\s*= (?: "((?:[^\\"]++|\\.){0,4096}+)" | ([^;,\s]++) ) \s* }gcxso ); # "
											}
										}
										elsif ($part =~ /\G\015?\012/sxogc) {
											last;
										}
										elsif($part =~ /\G [^\012]* \Z/sxogc) {
											# Truncated part???
											last;
										}
										else {
											pos($part) = 0;
											last;
										}
									}
									substr($part, 0,pos($part),'');
									my $enc = lc $hd{'content-transfer-encoding'};
									if ( $enc eq 'quoted-printable' ) {
										require Encode;
										$MIME = Encode::find_encoding('MIME-Header');
										$part = $MIME->decode( $part );
									}

									elsif ( $enc eq 'base64' ) {
										require MIME::Base64;
										$part = MIME::Base64::decode_base64( $part ); 
									}
									$hd{filename} = $hd{'content-disposition+filename'} if exists $hd{'content-disposition+filename'};
									$hd{name}     = $hd{'content-disposition+name'}     if exists $hd{'content-disposition+name'};
									#warn "call for part $hd{name} ($last)";
									$cb->( $last && $idx == -1 ? 1 : 0,$part,\%hd );
								}
								#warn "just return";
								#if ($last) {
								#warn "leave with $body";
								#}
							};
						}
						#										elsif ( $h{'content-type'} =~ m{^application/x-www-form-urlencoded(?:\Z|\s*;)}i and exists $rv[0]{form} ) {

						elsif (  exists $rv[0]{form} ) {
							my $body = '';
							$r{on_body} = sub {
								my ($last,$part) = @_;
								if ( length($body) + length($$part) > $self->{max_body_size} ) {
									# TODO;
								}
								$body .= $$part;
								if ($last) {
									$rv[0]{form}( $req->form($body), $body );
									delete $r{on_body};
								}
							};
						}
						elsif( exists $rv[0]{raw} ) {
							$r{on_body} = $rv[0]{raw};
						}
						else {
							die "XXX";
						}
					}
					elsif ($rv[0] eq 'HANDLE') {
						delete $r{rw};
						my $h = AnyEvent::Handle->new(
							fh => $fh,
						);
						$h->{rbuf} = substr($buf,$pos);
						#warn "creating handle ".Dumper $h->{rbuf};
						$req->[3] = sub {
							my $rbuf = shift;
							if (defined $$rbuf) {
								if ($h) {
									$h->push_write( $$rbuf );
								}
								else {
									warn "Requested write '$$rbuf' on destroyed handle";
								}
							} else {
								if ($h) {
									$h->push_shutdown;
									$h->on_drain(sub {
											$h->destroy;
											undef $h;
											$self->drop($id) if $self;
										});
									undef $h;
								}
								else {
									$self->drop($id) if $self;
								}
							}
						};
						weaken($req->[11] = $h);
						$rv[1]->($h);
						weaken($req);
						%r = ( );
						return;
					}
					elsif ( $rv[0] ) {
						#print "NORMAL REPLY\n";
						$req->reply(@rv);
					}
					else {
						#warn "Other rv";
					}
				}
				weaken($req);

				if( $len = $h{'content-length'} ) {
					#warn "have clen";
					if ( length($buf) - $pos == $len ) {
						#warn "Equally";
						$r{on_body} && (delete $r{on_body})->( 1, \(substr($buf,$pos)) );
						$buf = '';$state = $ixx = 0;
						#TEST && test_visited("finish:complete content length")
						# FINISHED
						#warn "1. finished request" . Dumper $req;
						return;
					}
					elsif ( length($buf) - $pos > $len ) {
						#warn "Complete body + trailing (".( length($buf) - $pos - $len )." bytes: ".substr( $buf,$pos + $len ).")";
						$r{on_body} && (delete $r{on_body})->( 1, \(substr($buf,$pos,$pos+$len)) );
						$ixx = $pos + $len;
						$state = 0;
						# FINISHED
						#warn "2. finished request" . Dumper $req;
						redo;
					}
					else {
						#warn "Not enough body";
						$r{left} = $len - ( length($buf) - $pos );
						if ($r{on_body}) {
							$r{on_body}( 0, \(substr($buf,$pos)) ) if $pos < length $buf;
							$state = 2;
						} else {
							$state = 2;
						}
						$buf = ''; $ixx = 0;
						return;
					}
				}
				#elsif (chunked) { TODO }
				else {
					#warn "No clen";
					$r{on_body}(1,\('')) if $r{on_body};
					# FINISHED
					#warn "3. finished request" . Dumper($req);
					#warn "pos = $pos, lbuf=".length $buf;
					#return %r=() if $req->connection eq 'close';
					$state = 0;
					if ($pos < length $buf) {
						$ixx = $pos;
						redo;
					} else {
						$buf = '';$state = $ixx = 0;
						return;
					}
				}
			} # state 1
			elsif ($state == 2 ) {
				#warn "partial ".Dumper( $ixx, $buf, substr($buf,$ixx) );
				if (length($buf) - $ixx >= $r{left}) {
					#warn sprintf "complete (%d of %d)", length $buf, $r{left};
					$r{on_body} && (delete $r{on_body})->( 1, \(substr($buf,$ixx, $r{left})) );
					$buf = substr($buf,$ixx + $r{left});
					$state = $ixx = 0;
					# FINISHED
					#warn "4. finished request" . Dumper $req;
					#return $self->drop($id) if $req->connection eq 'close';
					#$ixx = $pos + $r{left};
					#$state = 0;
					redo;
				} else {
					#warn sprintf "not complete (%d of %d)", length $buf, $r{left};
					$r{on_body} && $r{on_body}( 0, \(substr($buf,$ixx)) );
					$r{left} -= ( length($buf) - $ixx );
					$buf = ''; $ixx = 0;
					#return;
					next;
				}
			}
			else {
			}
			#state 3: discard body

			#$r{_activity} = $r{_ractivity} = AE::now;
			#$write->(\("HTTP/1.1 200 OK\r\nContent-Length:10\r\n\r\nTestTest1\n"),\undef);
		} # while read
		return unless $self and exists $self->{$id};
		if (defined $len) {
			if (length $buf == MAX_READ_SIZE) {
				$self->badconn($fh,\$buf,"Can't read (@{[ MAX_READ_SIZE ]}), can't consume");
				# $! = Errno::EMSGSIZE; # Errno is useless, since not calling drop
				my $content = 'Non-consumable request';
				my $str = "HTTP/1.1 400 Bad Request${LF}Connection:close${LF}Content-Type:text/plain${LF}Content-Length:".length($content)."${LF}${LF}".$content;
				$self->{active_requests}--;
				$write->($str);
				$write->(undef);
				return;
			}
			else {
				# $! = Errno::EPIPE;
				# This is not an error, just EOF
			}
		} else {
			return if $! == EAGAIN or $! == EINTR or $! == WSAEWOULDBLOCK;
		}
		$self->drop($id, $! ? "$!" : ());
	}; # io
}

sub ws_close {
	my $self = shift;
	for (values %{ $self->{wss} }) {
		$_ && $_->close();
	}
	warn "$self->{active_requests} / $self->{active_connections}";
}

sub graceful {
	my $self = shift;
	my $cb = pop;
	delete $self->{aws};
	close $_ for values %{ $self->{fhs} };
	if ($self->{active_requests} == 0 or $self->{active_connections} == 0) {
		$cb->();
	} else {
		$self->{graceful} = $cb;
		$self->ws_close();
	}
}


1; # End of AnyEvent::HTTP::Server
__END__

sub http_server($$&) {
	my ($lhost,$lport,$reqcb) = @_;
	
	# TBD
	
	return $self;
}

sub __old_stop {
	my ($self,$cb) = @_;
	delete $self->{aw};
	close $self->{socket};
	if (%{$self->{con}}) {
		$log->debugf("Server have %d active connectinos while stopping...", 0+keys %{$self->{con}});
		my $cv = &AE::cv( $cb );
		$cv->begin;
		for my $key ( keys %{$self->{con}} ) {
			my $con = $self->{con}{$key};
			$log->debug("$key: connection from $con->{host}:$con->{port}: $con->{state}");
			if ($con->{state} eq 'idle' or $con->{state} eq 'closed') {
				$con->close;
				delete $self->{con}{$key};
				use Devel::FindRef;
				warn "closed <$con> ".Devel::FindRef::track $con;
			} else {
				$cv->begin;
				$con->{close} = sub {
					$log->debug("Connection $con->{host}:$con->{port} was closed");
					$cv->end;
				};
			}
		}
		if (%{$self->{con}}) {
			$log->debug("Still have @{[ 0+keys %{$self->{con}} ]}");
		}
		$cv->end;
	} else {
		$cb->();
	}
}

=head1 SYNOPSIS

    use AnyEvent::HTTP::Server;
    my $s = AnyEvent::HTTP::Server->new(
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

AnyEvent::HTTP::Server is a very fast asynchronous HTTP server written in perl. 
It has been tested in high load production environments and may be considered both fast and stable.

One can easily implement own HTTP daemon with AnyEvent::HTTP::Server and Daemond::Lite module,
both found at L<https://github.com/Mons>

This is a second verson available as AnyEvent-HTTP-Server-II. The first version is now obsolette.

=head1 HANDLING REQUEST

You can handle HTTP request by passing cb parameter to AnyEvent::HTTP::Server->new() like this:


  my $dispatcher = sub {
    my $request = shift;
    #... Request processing code goes here ...
    1;
  };

  my $s = AnyEvent::HTTP::Server->new( host => '0.0.0.0', port => 80, cb => $dispatcher,);

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

  my $s = AnyEvent::HTTP::Server->new( host => '0.0.0.0', port => 80, cb => $dispatcher,);

=head1 EXPORT

  Does not export anything

=head1 SUBROUTINES/METHODS

=head2 new - create HTTP Server object

  Arguments to constractor should be passed as a key=>value list, for example

    my $s = AnyEvent::HTTP::Server->new(
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

  The first argument to callback will be request object (AnyEvent::HTTP::Server::Req).

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

=item * Thanks to B<Robin Redeker> for L<AnyEvent::HTTPD>

=back

=head1 AUTHOR

Mons Anderson, <mons@cpan.org>

=head1 LICENSE

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

=cut
