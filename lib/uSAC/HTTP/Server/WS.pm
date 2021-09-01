package uSAC::HTTP::Server::WS;
use common::sense;
use feature "refaliasing";
no warnings "experimental";

use Exporter 'import';
use MIME::Base64;		
use Digest::SHA1;
use Encode qw<decode encode>;
use Compress::Raw::Zlib qw(Z_SYNC_FLUSH);

our @EXPORT_OK=qw<upgrade_to_websocket>;
our @EXPORT=@EXPORT_OK;

use Data::Dumper;
use AnyEvent;
use Config;
use Time::HiRes ();
use JSON::XS;
use Scalar::Util 'weaken';

use uSAC::HTTP::Rex;
use uSAC::HTTP::Session;
use uSAC::HTTP::Header qw<:constants>;
use uSAC::HTTP::Code qw<:constants>;

use uSAC::HTTP::Middler;

my $LF=$uSAC::HTTP::Rex::LF;

use constant LF=>"\015\012";

our $JSON = JSON::XS->new->utf8->convert_blessed;

sub time64 () {
	int( Time::HiRes::time() * 1e6 );
}

sub DEBUG () { 0 }

use enum ( "writer_=0" ,qw<on_message_ on_close_ on_error_ session_>);

#Add a mechanism for sub classing
use constant KEY_OFFSET=>0;
use constant KEY_COUNT=>session_-writer_+1;

use constant {
	CONTINUATION => 0,
	TEXT         => 1,
	BINARY       => 2,
	CLOSE        => 8,
	PING         => 9,
	PONG         => 10,
	
	CONNECTING   => 1,
	OPEN         => 2,
	CLOSING      => 3,
	CLOSED       => 4,
};

our %OP = (
	CONTINUATION() => 'CONT',
	TEXT()         => 'TEXT',
	BINARY()       => 'BINR',
	CLOSE()        => 'CLOS',
	PING()         => 'PING',
	PONG()         => 'PONG',
);


sub onmessage {
	$_[0]{onmessage} = $_[1];
}

sub onerror {
	$_[0]{onerror} = $_[1];
}

sub onclose {
	$_[0]{onclose} = $_[1];
}

sub on_message {
	$_[0]{on_message_}=$_[1];
}
sub on_close {
	$_[0]{on_close_}=$_[1];
}
sub on_error {
	$_[0]{on_error_}=$_[1];
}



#must be utf8 encoded prior to calling this
sub send_utf8{
	my $self = shift;
	my $data = shift;
	$self->send_frame(1, 0, 0, 0, TEXT, $data);
}


#take http1.1 connection and make it websocket
#does the handshake
sub upgrade_to_websocket{
	DEBUG && say  "Testing for websocket";
	my $line=shift;
	my $rex=shift;
	#my $uri=shift;
	my $cb=shift;
	my $session=$rex->[uSAC::HTTP::Rex::session_];
	#attempt to do the match
	given ($rex->[uSAC::HTTP::Rex::headers_]){
		when (
				$_->{CONNECTION} =~ /upgrade/i	#required
				and  $_->{UPGRADE} =~ /websocket/i	#required
				and  $_->{'SEC_WEBSOCKET_VERSION'} ==13	#required
				and  exists $_->{'SEC_WEBSOCKET_KEY'}	#required
				and  $_->{'SEC_WEBsOCKET_PROTOCOL'} =~ /.*/  #sub proto
		){

			#TODO:  origin testing, externsions,
			# mangle the key
			my $key=MIME::Base64::encode_base64 
				Digest::SHA1::sha1( $_->{'SEC_WEBSOCKET_KEY'}."258EAFA5-E914-47DA-95CA-C5AB0DC85B11"),
				"";
			#
			#reply
			my $reply=
				"$rex->[uSAC::HTTP::Rex::version_] ".HTTP_SWITCHING_PROTOCOLS.LF
				.HTTP_CONNECTION.": Upgrade".LF
				.HTTP_UPGRADE.": websocket".LF
				.HTTP_SEC_WEBSOCKET_ACCEPT.": $key".LF
				;
			#support the permessage deflate
			my $deflate_flag;
			given($_->{'SEC_WEBSOCKET_EXTENSIONS'}){
				when(/permessage-deflate/){
					say "Permessage deflate";
					#$reply.= HTTP_SEC_WEBSOCKET_EXTENSIONS.": permessage-deflate".LF;
					#$deflate_flag=1;
				}
				default {
				}
			}

			#write reply	
			say $reply;
                        #####################################
                        # uSAC::HTTP::Session::push_writer  #
                        #         $session,                 #
                        #         "http1_1_default_writer", #
                        #         undef;                    #
                        #####################################
			local $/=", ";
			say $rex->[uSAC::HTTP::Rex::headers_]->%*;
			given($session->[uSAC::HTTP::Session::write_]){
				say "Writer is: ", $_;
				$_->( $reply.LF , sub {

						say "handshake written out";
						my $ws=uSAC::HTTP::Server::WS->new($session);
						$cb->($ws);

						#read and write setup create a new ws with just the session
						#uSAC::HTTP::Server::WS->new($_);


						$_=undef;
					});
			}

		}

		default {
			DEBUG && say "Websocket did not match";
			#reply
			say "NO WEBSOCKET ALLOWED";
			$session->[uSAC::HTTP::Session::closeme_]=1;
			uSAC::HTTP::Rex::reply_simple $line, $rex, HTTP_FORBIDDEN, undef,"";
			return;
		}
	}
}


#This is called by the session reader. Data is in the scalar ref $buf
sub make_websocket_server_reader {
	my $self=shift;
	my $session=shift;	#session
	#my $ws=shift;		#websocket

	\my $buf=\$session->[uSAC::HTTP::Session::rbuf_];
	\my $fh=$session->[uSAC::HTTP::Session::fh_];
	my $rex=$session->[uSAC::HTTP::Session::rex_];
	my $writer=$rex->{writer};

	my ($fin, $rsv1, $rsv2, $rsv3,$op, $mask, $len);
	my $head;
	my $masked;
	my $payload="";
	my $hlen;
	my $mode;
	\my $on_fragment=\$self->{on_message_};#$session->[uSAC::HTTP::Session::reader_cb_];
	say "ON FRAGMENT: ", $on_fragment;
	sub {
		say "IN WS READER";
		#do the frame parsing here
		say $buf;
		while( length $buf> 2){
			#return if length $buf < 2;	#do
			my $head = substr $buf, 0, 2;
			$fin  = (vec($head, 0, 8) & 0b10000000) == 0b10000000 ? 1 : 0;
			$rsv1 = (vec($head, 0, 8) & 0b01000000) == 0b01000000 ? 1 : 0;
			#warn "RSV1: $rsv1\n" if DEBUG;
			$rsv2 = (vec($head, 0, 8) & 0b00100000) == 0b00100000 ? 1 : 0;
			#warn "RSV2: $rsv2\n" if DEBUG;
			$rsv3 = (vec($head, 0, 8) & 0b00010000) == 0b00010000 ? 1 : 0;
			#warn "RSV3: $rsv3\n" if DEBUG;

			# Opcode
			$op = vec($head, 0, 8) & 0b00001111;
			warn "OPCODE: $op ($OP{$op})\n" if DEBUG;

			# Length
			my $len = vec($head, 1, 8) & 0b01111111;
			warn "LENGTH: $len\n" if DEBUG;

			# No payload
			given($len){
				when (0) {
					$hlen = 2;
					warn "NOTHING\n" if DEBUG;
				}
				when($_< 126){
					$hlen = 2;
					warn "SMALL\n" if DEBUG;
				}
				when(126){
					# 16 bit extended payload length
					return unless length $buf > 4;
					$hlen = 4;
					my $ext = substr $buf, 2, 2;
					$len = unpack 'n', $ext;
					warn "EXTENDED (16bit): $len\n" if DEBUG;
				}
				when(127){

					# Extended payload (64bit)
					return unless length $buf > 10;
					$hlen = 10;
					my $ext = substr $buf, 2, 8;
					$len =
					$Config{ivsize} > 4
					? unpack('Q>', $ext)
					: unpack('N', substr($ext, 4, 4));
					warn "EXTENDED (64bit): $len\n" if DEBUG;
				}
				default {
					#error if here
				}
			}



			# Check if whole packet has arrived
			#
			$masked = vec($head, 1, 8) & 0b10000000;
			return if length $buf < ($len + $hlen + ($masked ? 4 : 0));

			#substr $buf, 0, $hlen, '';	#clear the header
			


			$len += 4 if $masked;
			return if length $buf < $len;
			#$payload = $len ? substr($buf, 0, $len, '') : '';

			#$payload="" if $op == TEXT or $op == BINARY;

			given($op){
				when(TEXT){
					#check payload can be decoded
					$mode=TEXT;
					$payload="";
					if ($masked) {
						warn "UNMASKING PAYLOAD\n" if DEBUG;
						my $mask = substr($buf, $hlen, 4);
						$payload = _xor_mask(($len ? substr($buf, $hlen, $len) : ''), $mask);
						#say xd $payload;
					}

					else {
						$payload=$len ? substr($buf, $hlen, $len, '') : '';
					}
					substr $buf,0, $hlen+$len,'';
					if($fin){
						#decode
						#do callback
						$on_fragment->(decode("UTF-8",$payload ));
						$on_fragment->(undef);

						next;
					}


				}
				when(BINARY){
					$mode=BINARY;
					if ($masked) {
						warn "UNMASKING PAYLOAD\n" if DEBUG;
						my $mask = substr($buf, $hlen, 4);
						$on_fragment->(xor_mask(($len ? substr($buf, $hlen, $len) : ''), $mask));
						#say xd $payload;
					}

					else {
						$on_fragment->($len ? substr($buf, $hlen, $len, '') : '');
					}
					substr $buf,0, $hlen+$len,'';
					if($fin){
						$on_fragment->(undef);
					}
						next;


				}
				when(CONTINUATION){

					if ($masked) {
						warn "UNMASKING PAYLOAD\n" if DEBUG;
						my $mask = substr($payload, $hlen, 4, '');

						if($mode==TEXT){
							$payload .= _xor_mask(($len ? substr($buf, $hlen, $len, '') : ''), $mask);
						}
						else {
							$on_fragment->($len ? substr($buf, $hlen, $len, '') : '');
						}
					}

					substr $buf,0, $hlen+$len,'';
					if($fin){
						#decode text
						$on_fragment->( utf8::decode( $payload )) if $mode== TEXT;
						$on_fragment->(undef);
					}
					next;

				}
				when(PING){
					#do not change accumulating payload
					#reply directly with PONG
					if ($masked) {
						warn "UNMASKING PAYLOAD\n" if DEBUG;
						my $mask = substr($buf, $hlen, 4);
						$writer->(1,0,0,0,xor_mask(($len ? substr($buf, $hlen, $len) : ''), $mask));
						#say xd $payload;
					}

					else {
						$writer->(1,0,0,0,$len ? substr($buf, $hlen, $len, '') : '');
					}
					substr $buf,0, $hlen+$len,'';
					next;

				}
				when(PONG){
					#do not change accumulating payload
					say "GOT PONG";
					substr $buf,0, $hlen+$len,'';
					next;
				}
				when(PING){
					say "GOT PING";

					substr $buf,0, $hlen+$len,'';
					next;
				}
				when(CLOSE){
					say "GOT CLOSE";
					substr $buf,0, $hlen+$len,'';
					#TODO: drop the session, undef any read/write subs
					$self->{pinger}=undef;
					$self->{on_close_}->();
					$session->drop;

				}
				default{
				}
			}

			#do on message if fin is set

			#say "FIN $fin RSV1 $rsv1 RSV2 $rsv2 RSV3 $rsv3 op $op, $payload";
			#return [$fin, $rsv1, $rsv2, $rsv3, $op, $payload];

			#Frame is parsed. So now what do we do?



		}
	}

}

sub _websocket_writer {
	my $next =shift;	# This is the reference to the next item in the stack

	sub {
		#take input data, convert to frame and use normal writer?
		my ($fin, $rsv1, $rsv2, $rsv3, $op, $payload, $cb,$arg) = @_;
		$cb//=sub {};		#if no callback provided, fire and forget
		$arg//=__SUB__;		#Use 'self' as argument if none provided
		warn "BUILDING FRAME\n" if DEBUG;

		# Head
		my $frame = 0b00000000;
		say "fin is $fin";
		say "op is $op";

                #################################################
                # vec($frame, 0, 8) = $op | 0b10000000 if $fin; #
                # vec($frame, 0, 8) |= 0b01000000 if $rsv1;     #
                # vec($frame, 0, 8) |= 0b00100000 if $rsv2;     #
                # vec($frame, 0, 8) |= 0b00010000 if $rsv3;     #
                #################################################

		#vec($frame, 0, 8) = 
		$frame= pack "C", $op 
		| ($fin && 0b10000000)
		| ($rsv1 && 0b01000000) 
		| ($rsv2 && 0b00100000)
		| ($rsv3 && 0b00010000);
		say "Frame ",unpack "H*",$frame;
		#printf "Frame: %X\n",$frame;
		my $len = length $payload;
		# Mask payload
		warn "PAYLOAD: $payload\n" if DEBUG;
		my $masked =0;	
		if ($masked) {
			warn "MASKING PAYLOAD\n" if DEBUG;
			my $mask = pack 'N', int(rand( 2**32 ));
			$payload = $mask . _xor_mask($payload, $mask);
		}

		# Length
		#my $len = length $payload;
		#$len -= 4 if $self->{masked};

		# Empty prefix
		my $prefix = 0;

		# Small payload
		if ($len < 126) {
			vec($prefix, 0, 8) = $masked ? ($len | 0b10000000) : $len;
			$frame .= $prefix;
		}

		# Extended payload (16bit)
		elsif ($len < 65536) {
			vec($prefix, 0, 8) = $masked ? (126 | 0b10000000) : 126;
			$frame .= $prefix;
			$frame .= pack 'n', $len;
		}

		# Extended payload (64bit)
		else {
			vec($prefix, 0, 8) = $masked ? (127 | 0b10000000) : 127;
			$frame .= $prefix;
			$frame .=
			$Config{ivsize} > 4
			? pack('Q>', $len)
			: pack('NN', $len >> 32, $len & 0xFFFFFFFF);
		}

		if (DEBUG) {
			warn 'HEAD: ', unpack('B*', $frame), "\n";
			warn "OPCODE: $op\n";
		}

		# Payload
		$frame .= $payload;
		print "Built frame = \n".xd( "$frame" ) if DEBUG;

		say "FRAME TO SEND ",$frame;
		say "NEXT is : ", $next;
		$next->($frame,$cb,$arg);
		return;
	}
}

#sub which links the websocket to socket stream
#
sub make_websocket_server_writer {
	my $self=shift;
	my $session=shift;	#session

	my ($entry_point,$stack)=uSAC::HTTP::Middler->new()
		->register(\&_websocket_writer)
		->link($session->[uSAC::HTTP::Session::write_]);
	return $entry_point;
}


sub new {
	my $pkg = shift;
	my $session=shift;
	#my $on_fragment=shift;
	
	my %args = @_;
	my $h = $args{h};
	my $self = bless {
		#on_fragment=>$on_fragment,
		session=>$session,
		maxframe      => 1024*1024,
		mask          => 0,
		ping_interval => 2,
		state         => OPEN,
		on_message_ => sub {say "Default on message"},
		on_error_	=> sub { say "Default on error"},
		on_close_	=> sub { say "Default on close"},
		
		%args,
	}, $pkg;
	$session->[uSAC::HTTP::Session::rex_]=$self;	#update rex to refer to the websocket
	$session->[uSAC::HTTP::Session::closeme_]=1;	#At the end of the session close the socket
	$self->{writer_}=make_websocket_server_writer $self, $session;	#create a writer and store in ws
	say "Created writer: ",$self->{writer_};

	#the pushed reader now has access to the writer via the session->rex
	$session->[uSAC::HTTP::Session::read_]=make_websocket_server_reader($self,$session);
	$session->[uSAC::HTTP::Session::reader_cb_]=undef;

	#setup ping
	$self->{pinger} = AE::timer 0,$self->{ping_interval}, sub {
		say "Sending ping";
		$self->{ping_id} = "hello";#time64();
		$self->{writer_}->( 1,0,0,0, PING, $self->{ping_id});
                #########################################################
                # ,sub {                                                #
                #                 say "WRITER CALLBACK";                #
                #                 if($_[0]){                            #
                #                         say "good to go again";       #
                #                 }                                     #
                #                 else{                                 #
                #                         say "ERROR... need to close"; #
                #                         $self->{pinger}=undef;        #
                #                         $session->drop;               #
                #                                                       #
                #                 }                                     #
                #         });                                           #
                #########################################################
	} if $self->{ping_interval} > 0;

	return $self;
}


sub destroy {
	my $self = shift;
	$self->{h} and (delete $self->{h})->destroy;
	#delete @{$self}{qw(onmessage onerror onclose)};
	#clean all except...
	%$self = (
		state => $self->{state}
	);
}


sub _xor_mask($$) {
	$_[0] ^
	(
		$_[1] x (length($_[0])/length($_[1]) )
		. substr($_[1],0,length($_[0]) % length($_[1]))
	);
}

sub write_text {
	$_[0]->{writer_}->(1,0,0,0,TEXT,$_[1]);
}

sub write_binary {
	$_[0]->{writer_}->(1,0,0,0,BINARY,$_[1]);

}

#############################################################################
# sub parse_frame {                                                         #
#         my ($self,$rbuf) = @_;                                            #
#         return if length $$rbuf < 2;                                      #
#         my $clone = $$rbuf;                                               #
#         #say "parsing frame: \n".xd "$clone";                             #
#         my $head = substr $clone, 0, 2;                                   #
#         my $fin  = (vec($head, 0, 8) & 0b10000000) == 0b10000000 ? 1 : 0; #
#         my $rsv1 = (vec($head, 0, 8) & 0b01000000) == 0b01000000 ? 1 : 0; #
#         #warn "RSV1: $rsv1\n" if DEBUG;                                   #
#         my $rsv2 = (vec($head, 0, 8) & 0b00100000) == 0b00100000 ? 1 : 0; #
#         #warn "RSV2: $rsv2\n" if DEBUG;                                   #
#         my $rsv3 = (vec($head, 0, 8) & 0b00010000) == 0b00010000 ? 1 : 0; #
#         #warn "RSV3: $rsv3\n" if DEBUG;                                   #
#                                                                           #
#         # Opcode                                                          #
#         my $op = vec($head, 0, 8) & 0b00001111;                           #
#         warn "OPCODE: $op ($OP{$op})\n" if DEBUG;                         #
#                                                                           #
#         # Length                                                          #
#         my $len = vec($head, 1, 8) & 0b01111111;                          #
#         warn "LENGTH: $len\n" if DEBUG;                                   #
#                                                                           #
#         # No payload                                                      #
#         my $hlen = 2;                                                     #
#         if ($len == 0) { warn "NOTHING\n" if DEBUG }                      #
#                                                                           #
#         # Small payload                                                   #
#         elsif ($len < 126) { warn "SMALL\n" if DEBUG }                    #
#                                                                           #
#         # Extended payload (16bit)                                        #
#         elsif ($len == 126) {                                             #
#                 return unless length $clone > 4;                          #
#                 $hlen = 4;                                                #
#                 my $ext = substr $clone, 2, 2;                            #
#                 $len = unpack 'n', $ext;                                  #
#                 warn "EXTENDED (16bit): $len\n" if DEBUG;                 #
#         }                                                                 #
#                                                                           #
#         # Extended payload (64bit)                                        #
#         elsif ($len == 127) {                                             #
#                 return unless length $clone > 10;                         #
#                 $hlen = 10;                                               #
#                 my $ext = substr $clone, 2, 8;                            #
#                 $len =                                                    #
#                         $Config{ivsize} > 4                               #
#                         ? unpack('Q>', $ext)                              #
#                         : unpack('N', substr($ext, 4, 4));                #
#                 warn "EXTENDED (64bit): $len\n" if DEBUG;                 #
#         }                                                                 #
#                                                                           #
#                                                                           #
#         # TODO !!!                                                        #
#         # Check message size                                              #
#         #$self->finish and return if $len > $self->{maxframe};            #
#                                                                           #
#                                                                           #
#         # Check if whole packet has arrived                               #
#         my $masked = vec($head, 1, 8) & 0b10000000;                       #
#         return if length $clone < ($len + $hlen + ($masked ? 4 : 0));     #
#         substr $clone, 0, $hlen, '';                                      #
#                                                                           #
#         # Payload                                                         #
#         $len += 4 if $masked;                                             #
#         return if length $clone < $len;                                   #
#         my $payload = $len ? substr($clone, 0, $len, '') : '';            #
#                                                                           #
#         # Unmask payload                                                  #
#         if ($masked) {                                                    #
#                 warn "UNMASKING PAYLOAD\n" if DEBUG;                      #
#                 my $mask = substr($payload, 0, 4, '');                    #
#                 $payload = _xor_mask($payload, $mask);                    #
#                 #say xd $payload;                                         #
#         }                                                                 #
#         warn "PAYLOAD: $payload\n" if DEBUG;                              #
#         $$rbuf = $clone;                                                  #
#                                                                           #
#         return [$fin, $rsv1, $rsv2, $rsv3, $op, $payload];                #
# }                                                                         #
#                                                                           #
#############################################################################
##############################################################################
# sub send_frame {                                                           #
#         my ($self, $fin, $rsv1, $rsv2, $rsv3, $op, $payload) = @_;         #
#         $self->{h} or return warn "No handle for sending frame";           #
#         warn "BUILDING FRAME\n" if DEBUG;                                  #
#                                                                            #
#         # Head                                                             #
#         my $frame = 0b00000000;                                            #
#         vec($frame, 0, 8) = $op | 0b10000000 if $fin;                      #
#         vec($frame, 0, 8) |= 0b01000000 if $rsv1;                          #
#         vec($frame, 0, 8) |= 0b00100000 if $rsv2;                          #
#         vec($frame, 0, 8) |= 0b00010000 if $rsv3;                          #
#                                                                            #
#         my $len = length $payload;                                         #
#         # Mask payload                                                     #
#         warn "PAYLOAD: $payload\n" if DEBUG;                               #
#         my $masked = $self->{mask};                                        #
#         if ($masked) {                                                     #
#                 warn "MASKING PAYLOAD\n" if DEBUG;                         #
#                 my $mask = pack 'N', int(rand( 2**32 ));                   #
#                 $payload = $mask . _xor_mask($payload, $mask);             #
#         }                                                                  #
#                                                                            #
#         # Length                                                           #
#         #my $len = length $payload;                                        #
#         #$len -= 4 if $self->{masked};                                     #
#                                                                            #
#         # Empty prefix                                                     #
#         my $prefix = 0;                                                    #
#                                                                            #
#         # Small payload                                                    #
#         if ($len < 126) {                                                  #
#                 vec($prefix, 0, 8) = $masked ? ($len | 0b10000000) : $len; #
#                 $frame .= $prefix;                                         #
#         }                                                                  #
#                                                                            #
#         # Extended payload (16bit)                                         #
#         elsif ($len < 65536) {                                             #
#                 vec($prefix, 0, 8) = $masked ? (126 | 0b10000000) : 126;   #
#                 $frame .= $prefix;                                         #
#                 $frame .= pack 'n', $len;                                  #
#         }                                                                  #
#                                                                            #
#         # Extended payload (64bit)                                         #
#         else {                                                             #
#                 vec($prefix, 0, 8) = $masked ? (127 | 0b10000000) : 127;   #
#                 $frame .= $prefix;                                         #
#                 $frame .=                                                  #
#                         $Config{ivsize} > 4                                #
#                         ? pack('Q>', $len)                                 #
#                         : pack('NN', $len >> 32, $len & 0xFFFFFFFF);       #
#         }                                                                  #
#                                                                            #
#         if (DEBUG) {                                                       #
#                 warn 'HEAD: ', unpack('B*', $frame), "\n";                 #
#                 warn "OPCODE: $op\n";                                      #
#         }                                                                  #
#                                                                            #
#         # Payload                                                          #
#         $frame .= $payload;                                                #
#         print "Built frame = \n".xd( "$frame" ) if DEBUG;                  #
#                                                                            #
#         $self->{h}->push_write( $frame );                                  #
#         return;                                                            #
# }                                                                          #
#                                                                            #
##############################################################################
##############################################################################
# sub send : method {                                                        #
#         my $self = shift;                                                  #
#         my $data = shift;                                                  #
#         my $is_text;                                                       #
#         if (ref $data) {                                                   #
#                 $is_text = 1;                                              #
#                 $data = $JSON->encode($data);                              #
#         }                                                                  #
#         elsif ( utf8::is_utf8($data) ) {                                   #
#                 if ( utf8::downgrade($data,1) ) {                          #
#                                                                            #
#                 }                                                          #
#                 else {                                                     #
#                         $is_text = 1;                                      #
#                         utf8::encode($data);                               #
#                 }                                                          #
#         }                                                                  #
#         $self->send_frame(1, 0, 0, 0, ($is_text ? TEXT : BINARY ), $data); #
# }                                                                          #
##############################################################################

################################################################################################
# sub close : method {                                                                         #
# =for rem                                                                                     #
#    1000                                                                                      #
#                                                                                              #
#       1000 indicates a normal closure, meaning that the purpose for                          #
#       which the connection was established has been fulfilled.                               #
# =cut                                                                                         #
#         my $self = shift;                                                                    #
#         my $cb = pop;                                                                        #
#         my $code = shift // 1000;                                                            #
#         my $msg = shift;                                                                     #
#         if ($self->{state} == OPEN) {                                                        #
#                 $self->send_frame(1,0,0,0,CLOSE,pack("na*",$code,$msg));                     #
#                 $self->{state} = CLOSING;                                                    #
#                 $self->{close_cb} = shift;                                                   #
#         }                                                                                    #
#         elsif ($self->{state} == CLOSING) {                                                  #
#                 return;                                                                      #
#         }                                                                                    #
#         elsif ($self->{state} == CLOSED) {                                                   #
#                 warn "called close, while already closed from @{[ (caller)[1,2] ]}";         #
#         }                                                                                    #
#         else {                                                                               #
#                 warn "close not possible in state $self->{state} from @{[ (caller)[1,2] ]}"; #
#         }                                                                                    #
# }                                                                                            #
#                                                                                              #
################################################################################################
sub DESTROY {
	my $self = shift;
	my $caller = "@{[ (caller)[1,2] ]}";
	if ($self->{h} and $self->{state} != CLOSED) {
		warn "initiate close by DESTROY";
		my $copy = bless {%$self}, 'AnyEvent::HTTP::Server::WS::CLOSING';
		$copy->close(sub {
			warn "closed";
			undef $copy;
		});
	}
	#warn "Destroy ws $self by $caller";
	%$self = ();
}

package AnyEvent::HTTP::Server::WS::CLOSING;

our @ISA = qw(uSAC::HTTP::Server::WS);

sub DESTROY {
	
}

1;
