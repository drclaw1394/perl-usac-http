#package AnyEvent::HTTP::Server::Form;

package uSAC::HTTP::Rex;
use version; our $VERSION = version->declare('v0.1');
use common::sense;
use feature "refaliasing";


BEGIN {
	use uSAC::HTTP::Code qw<:constants>;
	use uSAC::HTTP::Header qw<:constants>;
}
use constant LF => "\015\012";

use constant STATIC_HEADERS=>
HTTP_SERVER.": ".uSAC::HTTP::Server::NAME."/".uSAC::HTTP::Server::VERSION." ".join(" ", @uSAC::HTTP::Server::Subproducts).LF
;

use uSAC::HTTP::Session;
use uSAC::HTTP::Server;
use AnyEvent;




########################################
# {                                    #
# package #hide                        #
#         aehts::sv;                   #
# use overload                         #
#         '""' => sub { ${$_[0]} },    #
#         '@{}' => sub { [${$_[0]}] }, #
#         fallback => 1;               #
# package #hide                        #
#         aehts::av;                   #
# use overload                         #
#         '""' => sub { $_[0][0] },    #
#         fallback => 1;               #
# }                                    #
########################################

#use AnyEvent::HTTP::Server::Kit;
#use uSAC::HTTP::Server::WS;
use Time::HiRes qw/gettimeofday/;
#use MIME::Base64 qw(encode_base64);
use Scalar::Util qw(weaken);
#use Digest::SHA1 'sha1';

	our @hdr = map { lc $_ }
	our @hdrn  = qw(
		Access-Control-Allow-Credentials Access-Control-Allow-Origin Access-Control-Allow-Headers
		Upgrade Connection Content-Type WebSocket-Origin WebSocket-Location Sec-WebSocket-Origin Sec-Websocket-Location Sec-WebSocket-Key Sec-WebSocket-Accept Sec-WebSocket-Protocol DataServiceVersion);
	our %hdr; @hdr{@hdr} = @hdrn;
	our %hdri; @hdri{ @hdr } = 0..$#hdr;
	our $LF = "\015\012";
	our $JSON;
	our $JSONP;
	our %http = do {
		local ($a,$b);
		my @w = qw(Content Entity Error Failed Found Gateway Large Proxy Request Required Timeout);
		map { ++$a;$b=0;map+(100*$a+$b++=>$_)x(!!$_),@$_; }
			["Continue","Switching Protocols","Processing",],
			[qw(OK Created Accepted),"Non-Authoritative Information","No $w[0]","Reset $w[0]","Partial $w[0]","Multi-Status",],
			["Multiple Choices","Moved Permanently","$w[4]","See Other","Not Modified","Use $w[7]",0,"Temporary Redirect",],
			["Bad $w[8]","Unauthorized","Payment $w[9]","Forbidden","Not $w[4]","Method Not Allowed","Not Acceptable","$w[7] Authentication $w[9]","$w[8] $w[10]","Conflict","Gone","Length $w[9]","Precondition $w[3]","$w[8] $w[1] Too $w[6]","$w[8]-URI Too $w[6]","Unsupported Media Type","$w[8] Range Not Satisfiable","Expectation $w[3]",(0)x4,"Unprocessable $w[1]","Locked","$w[3] Dependency","No code","Upgrade $w[9]",(0)x22,"Retry with",],
			["Internal Server $w[2]","Not Implemented","Bad $w[5]","Service Unavailable","$w[5] $w[10]","HTTP Version Not Supported","Variant Also Negotiates","Insufficient Storage",0,"Bandwidth Limit Exceeded","Not Extended",(0)x88,"Client $w[2]",],
	};
		

#Class attribute keys
use enum (
	"version_=0" ,qw<session_ method_ uri_ headers_ write_ chunked_ parsed_uri_ query_ reqcount_ server_ time_ ctx_ handle_ attrs_>
);

#Add a mechanism for sub classing
use constant KEY_OFFSET=>0;
use constant KEY_COUNT=>attrs_-method_+1;


		sub connection { $_[0][headers_]{connection} =~ /^([^;]+)/ && lc( $1 ) }
		
		sub method  { $_[0][method_] }
		sub full_uri { 'http://' . $_[0][headers_]{host} . $_[0][uri_] }
		sub uri     { $_[0][uri_] }
		sub headers { $_[0][headers_] }
		sub attrs   { $_[0][attrs_] //= {} }
		sub server  { $_[0][server_] }

		sub replied {
			my $r = shift;
			if (@_) {
				$r->attrs->{replied} = shift;
			}
			else {
				$r->attrs->{replied};
			}
		}
		
		sub url_unescape($) {
			# return undef unless defined $_[0];
			my $string = shift;
			$string =~ s/\+/ /sg;
			#return $string if index($string, '%') == -1;
			$string =~ s/%([[:xdigit:]]{2})/chr(hex($1))/ge;
			utf8::decode $string;
			return $string;
		}
		
		sub form {
			my %h;
			while ( $_[1] =~ m{ \G ([^=]+) = ([^&]*) ( & | \Z ) }gcxso ) {
				my $k = url_unescape($1);
				my $v = bless do{\(my $o = url_unescape($2))}, 'aehts::sv';
				if (exists $h{$k}) {
					if (UNIVERSAL::isa($h{$k}, 'ARRAY')) {
						push @{$h{$k}},$v;
					} else {
						$h{$k} = bless [ $h{$k},$v ], 'aehts::av';
					}
				}
				else {
					$h{$k} = $v;
				}
			}
			return \%h;
		}
		
		sub uri_parse {
			$_[0][parsed_uri_] = [
				$_[0][uri_] =~ m{ ^
					(?:
						(?:(?:([a-z]+):|)//|)
						([^/]+)
					|)
					(/[^?]*)
					(?:
						\? (.+|)
						|
					)
				$ }xso
			];
			# $_[0][5][2] = url_unescape( $_[0][5][2] );
			$_[0][query_] = +{ map { my ($k,$v) = split /=/,$_,2; +( url_unescape($k) => url_unescape($v) ) } split /&/, $_[0][parsed_uri_][3] };
		}
		
		
		sub path    {
			$_[0][parsed_uri_] or $_[0]->uri_parse;
			$_[0][parsed_uri_][2];
		}
		
		sub query    {
			$_[0][parsed_uri_] or $_[0]->uri_parse;
			$_[0][parsed_uri_][3];
		}
		
		sub params {
			$_[0][query_] or $_[0]->uri_parse;
			$_[0][query_];
		}
		
		sub param {
			$_[0][query_] or $_[0]->uri_parse;
			if ($_[1]) {
				return $_[0][query_]{$_[1]};
			} else {
				return keys %{ $_[0][query_] };
			}
		}
		our $CALLDEPTH = 1;
		
		sub replyjs {
			my $self = shift;
			#warn "Replyjs: @_ by @{[ (caller)[1,2] ]}";
			my ($code,$data,%args);
			$code = ref $_[0] ? 200 : shift;
			$data = shift;
			%args = @_;
			$args{headers} ||= {};
			$args{headers}{'content-type'} ||= 'application/json';
			my $pretty = delete $args{pretty};
			my $callback_name = delete $args{jsonp_callback};
			!$callback_name or $callback_name =~ /^[a-zA-Z_][0-9a-zA-Z_]*$/ or do {
				warn "jsonp callbackname is invalid $callback_name. Called from @{[ (caller)[1,2] ]}\n";
				$self->reply(500,'{error: "Internal Server Error" }', %args);
				return;
			};
			$JSON or do {
				eval { require JSON::XS;1 }
					or do {
						warn "replyjs required JSON::XS, which could not be loaded: $@. Called from @{[ (caller)[1,2] ]}\n";
						$self->reply(500,'{error: "Internal Server Error" }', %args);
						return;
					};
				$JSON  = JSON::XS->new->utf8;
				$JSONP = JSON::XS->new->utf8->pretty;
			};
			my $jdata = eval {
				($pretty ? $JSONP : $JSON)->encode( $data );
			};
			defined $jdata or do {
				warn "Can't encode to JSON: $@ at @{[ (caller)[1,2] ]}\n";
				$self->reply(500,'{error: "Internal Server Error"}', %args);
				return;
			};
			$jdata =~ s{<}{\\u003c}sg;
			$jdata =~ s{>}{\\u003e}sg;
			$jdata = "$callback_name( $jdata );" if $callback_name;
			local $CALLDEPTH = $CALLDEPTH + 1;
			$self->reply( $code, $jdata, %args );
			
		}
		
		sub sendfile {
			my $self = shift;
			my ( $code,$file,%args ) = @_;
			$code ||=200;

			if ($self->replied) {
				warn "Double reply $code from ".join(":", (caller $CALLDEPTH)[1,2])." prev was from ".$self->replied."\n";
				exit 255 if $self->server->{exit_on_double_reply};
				return;
			}
			$self->replied(join ":", (caller $CALLDEPTH)[1,2]);

			my $reply = "HTTP/1.0 $code $http{$code}$LF";
			my $size = -s $file or $! and return warn "Can't sendfile `$file': $!";
			open my $f, '<:raw',$file or return  warn "Can't open file `$file': $!";
			
			my @good;my @bad;
			my $h = {
				server           => 'aehts-'.$uSAC::HTTP::Server::VERSION,
				%{ $args{headers} || {} },
				'connection' => ( $args{headers} && $args{headers}{connection} ) ? $args{headers}{connection} : $self->connection,
				'content-length' => $size,
			};
			if (exists $h->{'content-type'}) {
				if( $h->{'content-type'} !~ m{[^;]+;\s*charset\s*=}
				and $h->{'content-type'} =~ m{(?:^(?:text/|application/(?:json|(?:x-)?javascript))|\+(?:json|xml)\b)}i) {
					$h->{'content-type'} .= '; charset=UTF-8';
				}
			} else {
				$h->{'content-type'} = 'application/octet-stream';
			}
			for (keys %$h) {
				if (exists $hdr{lc $_}) { $good[ $hdri{lc $_} ] = $hdr{ lc $_ }.": ".$h->{$_}.$LF; }
				else { push @bad, "\u\L$_\E: ".$h->{$_}.$LF; }
			}
			defined() and $reply .= $_ for @good,@bad;
			$reply .= $LF;
			if( $self->[write_] ) {
				$self->[write_]->( $reply );
				while ($size > 0) {
					my $l = sysread($f,my $buf,4096);
					defined $l or last;
					$size -= $l;
					$self->[write_]->( $buf );
				}
				#$self->[write_]->( undef ) if $h->{connection} eq 'close' or $self->[server_][graceful_];
				delete $self->[write_];
				${ $self->[reqcount_] }--;
			}
		}
		
		sub go {
			my $self = shift;
			my $location = shift;
			my %args = @_;
			( $args{headers} ||= {} )->{location} = $location;
			local $CALLDEPTH = $CALLDEPTH + 1;
			$self->reply( 302, "Moved", %args );
		}
	

		sub reply_GZIP {

		}
		#like simple reply but does a DEFLATE on the data.
		#Sets the headers accordingly
		sub reply_DEFLATE {
			#call replySimple with extra headers
		}


		#line,rex, cb
		#	cb args:
		#		data, headers
		#
		sub handle_form_upload {
			my $line=shift;
			my $rex=shift;
			my $cb=shift;
			my $session=$rex->[uSAC::HTTP::Rex::session_];
			$session->push_reader(
				"http1_1_form_data",
				$cb
			);
			$session->[uSAC::HTTP::Session::read_]->(\$session->[uSAC::HTTP::Session::rbuf_],$rex);

		}

		sub handle_upload {
			my $line=shift;
			my $rex=shift;	#rex object
			my $cb=shift;	#cb for parts
			my $session=$rex->[session_];
			$session->push_reader(
				"http1_1_urlencoded",
				$cb
			);

			#check for expects header and send 100 before trying to read
			given($rex->[uSAC::HTTP::Rex::headers_]){
				if(defined($_->{expects})){
					#issue a continue response	
					my $reply= "HTTP/1.1 ".HTTP_CONTINUE.LF.LF;
					$rex->[uSAC::HTTP::Rex::write_]->($reply);
				}
			}
			$session->[uSAC::HTTP::Session::read_]->(\$session->[uSAC::HTTP::Session::rbuf_],$rex);

		}


		#Reply the body and code specified. Adds Server and Content-Length headers
		#Line, Rex, code, header_ref, content
		sub reply_simple{
			use integer;
			my ($line, $self)=@_;
			#create a writer for the session
			my $session=$self->[session_];
			uSAC::HTTP::Session::push_writer 
			#$session->push_writer(
				$session,
				"http1_1_default_writer",
				undef;
				#);
			#$self->[write_]=$session->[uSAC::HTTP::Session::write_];

			my $reply="HTTP/1.1 $_[2]".LF;
			#my $reply="$self->[version_] $_[0]".LF;

			$reply.=
				STATIC_HEADERS
				.HTTP_DATE.": ".$uSAC::HTTP::Server::Date.LF
				.HTTP_CONTENT_LENGTH.": ".(length($_[4])+0).LF	#this always render content length
				;#if defined $_[1];	#Set server

				#TODO: benchmark length(undef)+0;
			
			#close connection after if marked
			if($session->[uSAC::HTTP::Session::closeme_]){
				$reply.=HTTP_CONNECTION.": close".LF;

			}

			#or send explicit keep alive?
			elsif($self->[version_] ne "HTTP/1.1") {
				$reply.=
					HTTP_CONNECTION.": Keep-Alive".LF
					.HTTP_KEEP_ALIVE.": timeout=5, max=1000".LF
				;
			}


			#User requested headers. 
			my $i=0;
			\my @headers=$_[3]//[];
			for(0..@headers/2-1){
				$reply.=$headers[$i++].": ".$headers[$i++].LF 
			}


			#Append body
			$reply.=LF.$_[4];

			#Write the headers
			#given ($self->[write_]){
			$session->[uSAC::HTTP::Session::write_]($reply);
			#$session->[uSAC::HTTP::Session::write_](
			#$self->[write_]( $reply );
			#$self->[write_]=undef;
				uSAC::HTTP::Session::drop $session;
				#}

		}
		
                ######################################################################################################################################
                # sub reply {                                                                                                                        #
                #         my $self = shift;                                                                                                          #
                #         #return $self->headers(@_) if @_ % 2;                                                                                      #
                #         say "in REPLY:";                                                                                                           #
                #         say caller;                                                                                                                #
                #         my ($code,$content,%args) = @_;                                                                                            #
                #         $code ||=200;                                                                                                              #
                #         #if (ref $content) {                                                                                                       #
                #         #       if (ref $content eq 'HASH' and $content->{sendfile}) {                                                             #
                #         #               $content->{size} = -s $content->{sendfile};                                                                #
                #         #       }                                                                                                                  #
                #         #       else {                                                                                                             #
                #         #               croak "Unknown type of content: $content";                                                                 #
                #         #       }                                                                                                                  #
                #         #                                                                                                                          #
                #         #} else {                                                                                                                  #
                #         #utf8::encode $content if utf8::is_utf8 $content;                                                                          #
                #         #}                                                                                                                         #
                #         my $reply = "HTTP/1.0 $code $http{$code}$LF";                                                                              #
                #         my @good;my @bad;                                                                                                          #
                #         my $h = {                                                                                                                  #
                #                 server           => 'aehts-'.$uSAC::HTTP::Server::VERSION,                                                         #
                #                 #'content-type+charset' => 'UTF-8';                                                                                #
                #                 %{ $args{headers} || {} },                                                                                         #
                #                 #'connection' => 'close',                                                                                          #
                #                 'connection' => ( $args{headers} && $args{headers}{connection} ) ? $args{headers}{connection} : $self->connection, #
                #         };                                                                                                                         #
                #         if ($self->method ne 'HEAD') {                                                                                             #
                #                 if ( exists $h->{'content-length'} ) {                                                                             #
                #                         if ($h->{'content-length'} != length($content)) {                                                          #
                #                                 warn "Content-Length mismatch: replied: $h->{'content-length'}, expected: ".length($content);      #
                #                                 $h->{'content-length'} = length($content);                                                         #
                #                         }                                                                                                          #
                #                 } else {                                                                                                           #
                #                         $h->{'content-length'} = length($content);                                                                 #
                #                 }                                                                                                                  #
                #         } else {                                                                                                                   #
                #                 if ( exists $h->{'content-length'} ) {                                                                             #
                #                         # keep it                                                                                                  #
                #                 }                                                                                                                  #
                #                 elsif(length $content) {                                                                                           #
                #                         $h->{'content-length'} = length $content;                                                                  #
                #                 }                                                                                                                  #
                #                 else {                                                                                                             #
                #                         $h->{'transfer-encoding'} = 'chunked';                                                                     #
                #                 }                                                                                                                  #
                #                 $content = '';                                                                                                     #
                #         }                                                                                                                          #
                #         if (exists $h->{'content-type'}) {                                                                                         #
                #                 if( $h->{'content-type'} !~ m{[^;]+;\s*charset\s*=}                                                                #
                #                 and $h->{'content-type'} =~ m{(?:^(?:text/|application/(?:json|(?:x-)?javascript))|\+(?:json|xml)\b)}i) {          #
                #                         $h->{'content-type'} .= '; charset=utf-8';                                                                 #
                #                 }                                                                                                                  #
                #         } else {                                                                                                                   #
                #                 $h->{'content-type'} = 'text/html; charset=utf-8';                                                                 #
                #         }                                                                                                                          #
                #         my $nh = delete $h->{NotHandled};                                                                                          #
                #         for (keys %$h) {                                                                                                           #
                #                 if (exists $hdr{lc $_}) { $good[ $hdri{lc $_} ] = $hdr{ lc $_ }.": ".$h->{$_}.$LF; }                               #
                #                 else { push @bad, "\u\L$_\E: ".$h->{$_}.$LF; }                                                                     #
                #         }                                                                                                                          #
                #         defined() and $reply .= $_ for @good,@bad;                                                                                 #
                #         # 2 is size of LF                                                                                                          #
                #         $self->attrs->{head_size} = length($reply) + 2;                                                                            #
                #         $self->attrs->{body_size} = length $content;                                                                               #
                #         $reply .= $LF.$content;                                                                                                    #
                #         #if (!ref $content) { $reply .= $content }                                                                                 #
                #         if( $self->[write_] ) {                                                                                                    #
                #                 $self->[write_]->( $reply );                                                                                       #
                #                 $self->[write_]->( undef ) if $h->{connection} eq 'close';# or $self->[server_][graceful_];                        #
                #                 delete $self->[write_];                                                                                            #
                #                 ${ $self->[reqcount_] }--;                                                                                         #
                #         }                                                                                                                          #
                #         if( $self->[server_] && $self->[server_]->{on_reply} ) {                                                                   #
                #                 $h->{ResponseTime} = gettimeofday() - $self->[time_];                                                              #
                #                 $h->{Status} = $code;                                                                                              #
                #                 $h->{NotHandled} = $nh if $nh;                                                                                     #
                #                 #eval {                                                                                                            #
                #                         $self->[server_]->{on_reply}->(                                                                            #
                #                                 $self,                                                                                             #
                #                                 $h,                                                                                                #
                #                         );                                                                                                         #
                #                 #1} or do {                                                                                                        #
                #                 #       warn "on_reply died with $@";                                                                              #
                #                 #};                                                                                                                #
                #         };                                                                                                                         #
                #                                                                                                                                    #
                #         if ($self->replied) {                                                                                                      #
                #                 warn "Double reply $code from ".join(":", (caller $CALLDEPTH)[1,2])." prev was from ".$self->replied."\n";         #
                #                 exit 255 if $self->server->{exit_on_double_reply};                                                                 #
                #                 return;                                                                                                            #
                #         }                                                                                                                          #
                #         $self->replied(join ":", (caller $CALLDEPTH)[1,2]);                                                                        #
                #                                                                                                                                    #
                #         if( $self->[server_] && $self->[server_]->{stat_cb} ) {                                                                    #
                #                 eval {                                                                                                             #
                #                         $self->[server_]->{stat_cb}->($self->path, $self->method, gettimeofday() - $self->[time_]);                #
                #                 1} or do {                                                                                                         #
                #                         warn "stat_cb died with $@";                                                                               #
                #                 }                                                                                                                  #
                #         };                                                                                                                         #
                # }                                                                                                                                  #
                ######################################################################################################################################
	 

                #########################################################################################################################################################
                # sub is_websocket {                                                                                                                                    #
                #         my $self = shift;                                                                                                                             #
                #         return 1 if lc($self->headers->{connection}) eq 'upgrade' and lc( $self->headers->{upgrade} ) eq 'websocket';                                 #
                #         return 0;                                                                                                                                     #
                # }                                                                                                                                                     #
                #                                                                                                                                                       #
                # sub upgrade {                                                                                                                                         #
                #         my $self = shift;                                                                                                                             #
                #         #my %h;$h{h} = \%h; $h{r} = $self;                                                                                                            #
                #                                                                                                                                                       #
                #         my $cb = pop;                                                                                                                                 #
                #         my %args = @_;                                                                                                                                #
                #         if ( $self->headers->{'sec-websocket-version'} == 13 ) {                                                                                      #
                #                 require MIME::Base64;                                                                                                                 #
                #                 require Digest::SHA1;                                                                                                                 #
                #                 my $key = $self->headers->{'sec-websocket-key'};                                                                                      #
                #                 my $origin = exists $self->headers->{'sec-websocket-origin'} ? $self->headers->{'sec-websocket-origin'} : $self->headers->{'origin'}; #
                #                 my $accept = MIME::Base64::encode_base64(Digest::SHA1::sha1( $key . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11' ));                        #
                #                 chomp $accept;                                                                                                                        #
                #                 $self->send_headers( 101,headers => {                                                                                                 #
                #                         %{ $args{headers} || {} },                                                                                                    #
                #                         upgrade => 'WebSocket',                                                                                                       #
                #                         connection => 'Upgrade',                                                                                                      #
                #                         'sec-websocket-accept' => $accept,                                                                                            #
                #                         #'sec-websocket-protocol' => 'chat',                                                                                          #
                #                 } );                                                                                                                                  #
                #                                                                                                                                                       #
                #                 ${ $self->[reqcount_] }--;                                                                                                            #
                #                                                                                                                                                       #
                #                 my $create_ws = sub {                                                                                                                 #
                #                         my $h = shift;                                                                                                                #
                #                         my $ws = uSAC::HTTP::Server::WS->new(                                                                                         #
                #                                 %args, h => $h,                                                                                                       #
                #                         );                                                                                                                            #
                #                         weaken( $self->[server_]{wss}{ 0+$ws } = $ws );                                                                               #
                #                         @$self = ();                                                                                                                  #
                #                         $cb->($ws);                                                                                                                   #
                #                 };                                                                                                                                    #
                #                                                                                                                                                       #
                #                 if ( $self->[handle_] ) {                                                                                                             #
                #                         $create_ws->($self->[handle_]);                                                                                               #
                #                         return                                                                                                                        #
                #                 }                                                                                                                                     #
                #                 else {                                                                                                                                #
                #                         return HANDLE => $create_ws                                                                                                   #
                #                 }                                                                                                                                     #
                #         }                                                                                                                                             #
                #         else {                                                                                                                                        #
                #                 $self->reply(400, '', headers => {                                                                                                    #
                #                         'sec-websocket-version' => 13,                                                                                                #
                #                 });                                                                                                                                   #
                #         }                                                                                                                                             #
                # }                                                                                                                                                     #
                #########################################################################################################################################################
		
		sub send_100_continue {
			my ($self,$code,%args) = @_;
			#my $reply = "HTTP/1.1 100 $http{100}$LF$LF";
			my $reply="$self->[version_] $uSAC::HTTP::Code::values[uSAC::HTTP::Code::Continue] $uSAC::HTTP::Code::names[uSAC::HTTP::Code::Continue]$LF$LF";

			$self->[write_]->( $reply );
		}

		sub send_headers {
			my ($self,$code,%args) = @_;
			$code ||= 200;

			if ($self->replied) {
				warn "Double reply $code from ".join(":", (caller $CALLDEPTH)[1,2])." prev was from ".$self->replied."\n";
				exit 255 if $self->server->{exit_on_double_reply};
				return;
			}
			$self->replied(join ":", (caller $CALLDEPTH)[1,2]);

			my $reply = "HTTP/1.1 $code $http{$code}$LF";
			my @good;my @bad;
			my $h = {
				%{ $args{headers} || {} },
				#'connection' => 'close',
				#'connection' => 'keep-alive',
				'connection' => ( $args{headers} && $args{headers}{connection} ) ? $args{headers}{connection} : $self->connection,
			};
			if (!exists $h->{'content-length'} and !exists $h->{upgrade}) {
				$h->{'transfer-encoding'} = 'chunked';
				$self->[chunked_]= 1;
			} else {
				$self->[chunked_]= 0;
			}
			for (keys %$h) {
				if (exists $hdr{lc $_}) { $good[ $hdri{lc $_} ] = $hdr{ lc $_ }.": ".$h->{$_}.$LF; }
				else { push @bad, "\u\L$_\E: ".$h->{$_}.$LF; }
			}
			defined() and $reply .= $_ for @good,@bad;
			$reply .= $LF;
			$h->{Status} = $code;
			$self->attrs->{sent_headers} = $h;
			$self->attrs->{head_size} = length $reply;
			$self->attrs->{body_size} = 0;
			#warn "send headers: $reply";
			$self->[write_]->( $reply );
			if (!$self->[chunked_]) {
				if ($args{clearance}) {
					$self->[write_] = undef;
				}
			}
		}
		
		sub body {
			my $self = shift;
			$self->[chunked_] or die "Need to be chunked reply";
			my $content = shift;
			utf8::encode $content if utf8::is_utf8 $content;
			$self->attrs->{body_size} += length $content;
			my $length = sprintf "%x", length $content;
			#warn "send body part $length / ".length($content)."\n";
			$self->[write_]->( ("$length$LF$content$LF") );
		}
		
		sub finish {
			my $self = shift;
			if ($self->[chunked_]) {
				#warn "send body end (".$self->connection.")\n";
				if( $self->[write_] ) {
					$self->[write_]->( ("0$LF$LF")  );
					$self->[write_]->(undef) if $self->connection eq 'close';# or $self->[server_][graceful_];
					delete $self->[write_];
				}
				undef $self->[chunked_];
			}
			elsif(defined $self->[chunked_]) {
				undef $self->[chunked_];
			}
			else {
				die "Need to be chunked reply";
			}
			${ $self->[reqcount_] }--;
			if ( $self->attrs->{sent_headers} ) {
				my $h = delete $self->attrs->{sent_headers};
				if( $self->[8] && $self->[8]->{on_reply} ) {
					$h->{ResponseTime} = gettimeofday() - $self->[9];
					$self->[8]->{on_reply}->(
						$self,
						$h,
					);
				};
			}
		}

		sub abort {
			my $self = shift;
			if( $self->[chunked_] ) {
				if( $self->[write_] ) {
					$self->[write_]->( ("1$LF"));
					$self->[write_]->( undef);
					delete $self->[write_];
				}
				undef $self->[chunked_];
			}
			elsif (defined $self->[chunked_]) {
				undef $self->[chunked_];
			}
			else {
				die "Need to be chunked reply";
			}
			${ $self->[reqcount_] }--;
			if ( $self->attrs->{sent_headers} ) {
				my $h = delete $self->attrs->{sent_headers};
				if( $self->[8] && $self->[8]->{on_reply} ) {
					$h->{ResponseTime} = gettimeofday() - $self->[9];
					$h->{SentStatus} = $h->{Status};
					$h->{Status} = "590";
					$self->[8]->{on_reply}->(
						$self,
						$h,
					);
				};
			}
		}
		
                #########################################################################################################################################################################################
                # sub DESTROY {                                                                                                                                                                         #
                #         my $self = shift;                                                                                                                                                             #
                #         my $caller = "@{[ (caller)[1,2] ]}";                                                                                                                                          #
                #         #warn "Destroy req $self->[0] $self->[1] by $caller";                                                                                                                         #
                #         if( $self->[write_] ) {                                                                                                                                                       #
                #                 local $@;                                                                                                                                                             #
                #                 eval {                                                                                                                                                                #
                #                         if ($self->[chunked_]) {                                                                                                                                      #
                #                                 $self->abort();                                                                                                                                       #
                #                         } else {                                                                                                                                                      #
                #                                 if( $self->[8] && $self->[8]->{on_not_handled} ) {                                                                                                    #
                #                                         $self->[8]->{on_not_handled}->($self, $caller);                                                                                               #
                #                                 }                                                                                                                                                     #
                #                                 if ($self->[write_]) {                                                                                                                                #
                #                                         $self->reply( 500, "Request not handled\n$self->[method_] $self->[uri_]\n", headers => { 'content-type' => 'text/plain', NotHandled => 1 } ); #
                #                                 }                                                                                                                                                     #
                #                         }                                                                                                                                                             #
                #                 1} or do {                                                                                                                                                            #
                #                         if ($EV::DIED) {                                                                                                                                              #
                #                                 @_ = ();                                                                                                                                              #
                #                                 goto &$EV::DIED;                                                                                                                                      #
                #                         } else {                                                                                                                                                      #
                #                                 warn "[E] Died in request DESTROY: $@ from $caller\n";                                                                                                #
                #                         }                                                                                                                                                             #
                #                 };                                                                                                                                                                    #
                #         }                                                                                                                                                                             #
                #         elsif (defined $self->[chunked_]) {                                                                                                                                           #
                #                 warn "[E] finish or abort was not called for ".( $self->[chunked_] ? "chunked" : "partial" )." response";                                                             #
                #                 $self->abort;                                                                                                                                                         #
                #         }                                                                                                                                                                             #
                #         @$self = ();                                                                                                                                                                  #
                # }                                                                                                                                                                                     #
                #########################################################################################################################################################################################



1;

__END__
