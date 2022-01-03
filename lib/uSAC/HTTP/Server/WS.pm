package uSAC::HTTP::Server::WS;
no warnings "experimental";
use feature qw<bitwise state say refaliasing current_sub>;

use Exporter 'import';
use MIME::Base64;		
use Digest::SHA1;
use Encode qw<decode encode>;
use IO::Compress::RawDeflate qw(rawdeflate $RawDeflateError) ;
use IO::Uncompress::RawInflate qw<rawinflate>;
#use Compress::Raw::Zlib qw(Z_SYNC_FLUSH);

our @EXPORT_OK=qw<usac_websocket>;
our @EXPORT=@EXPORT_OK;

use AnyEvent;
#use Config;

use uSAC::HTTP::Rex;
use uSAC::HTTP::Session;
use uSAC::HTTP::Header qw<:constants>;
use uSAC::HTTP::Code qw<:constants>;

use uSAC::HTTP::Middler;

my $LF=$uSAC::HTTP::Rex::LF;

use constant LF=>"\015\012";

use constant DEBUG => 0;


use enum ( "id_=0" ,qw<writer_ maxframe_ mask_ ping_interval_ ping_id_ pinger_ state_ on_open_ on_message_ on_fragment_ on_close_ on_error_ PMD_ message_buf_ session_>);

#Add a mechanism for sub classing
use constant KEY_OFFSET=>0;
use constant KEY_COUNT=>session_-id_+1;

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


use constant {
		FIN_FLAG =>0b10000000,
		RSV1_FLAG=>0b01000000,
		RSV2_FLAG=>0b00100000,
		RSV3_FLAG=>0b00010000,
	};

use enum qw<STATE_HEADER STATE_BODY>;


sub usac_websocket {
	my $parent=$_;
	my $cb=shift;

	sub {
		DEBUG && say  "Testing for websocket";
		my $line=shift;
		my $rex=shift;
		my $session=$rex->[uSAC::HTTP::Rex::session_];
		#attempt to do the match
		for ($rex->[uSAC::HTTP::Rex::headers_]){
			if(
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
				for($_->{'SEC_WEBSOCKET_EXTENSIONS'}){
					if(/permessage-deflate/){
						say "Permessage deflate";
						$reply.= HTTP_SEC_WEBSOCKET_EXTENSIONS.": permessage-deflate".LF;
						$deflate_flag=1;
					}
					else{
					}
				}

				#write reply	
				say $reply;
				local $/=", ";
				say $rex->[uSAC::HTTP::Rex::headers_]->%*;
				for($session->[uSAC::HTTP::Session::write_]){
					say "Writer is: ", $_;
					$_->($reply.LF , sub {

							say "handshake written out";
							my $ws=uSAC::HTTP::Server::WS->new($session);
							$ws->[PMD_]=$deflate_flag;
							$cb->($ws);
							#defer the open callback
							AnyEvent::postpone {$ws->[on_open_]->($ws, $ws->[id_])};

							#read and write setup create a new ws with just the session
							#uSAC::HTTP::Server::WS->new($_);
							$_=undef;
						});
				}
			}

			else{
				DEBUG && say "Websocket did not match";
				#reply
				say "NO WEBSOCKET ALLOWED";
				$session->[uSAC::HTTP::Session::closeme_]=1;
				uSAC::HTTP::Rex::reply_simple $line, $rex, HTTP_FORBIDDEN, undef,"";
				return;
			}
		}
	}
}


#This is called by the session reader. Data is in the scalar ref $buf
sub  _make_websocket_server_reader {
	my $self=shift;
	my $session=shift;	#session
	#my $ws=shift;		#websocket

	\my $fh=$session->[uSAC::HTTP::Session::fh_];
	my $rex=$session->[uSAC::HTTP::Session::rex_];
	my $writer=$rex->[uSAC::HTTP::Rex::write_];

	my ($fin, $rsv1, $rsv2, $rsv3,$op, $mask, $len);
	my $head;
	my $masked;
	my $payload="";
	my $hlen;
	my $mode;
	my $deflate_flag=$self->[PMD_];
	my $state=STATE_HEADER;	#0 header, 1 body
	\my $on_fragment=\$self->[on_message_];#$session->[uSAC::HTTP::Session::reader_cb_];
	say "ON FRAGMENT: ", $on_fragment;

	sub {
		\my $buf=\$_[1];
		state $do_deflate=0;
		#say "reader";
		#do the frame parsing here
		while($buf){
			#say "";
			#say "Input buffer: ", unpack "H*", $buf;
			if($state==STATE_HEADER){
				#say "parsing header";
				#header
				return if length $buf<2;
				($op,$len)=unpack "CC",$buf;#substr $buf, 0, 2;
				$fin=($op & FIN_FLAG)!=0;
				$rsv1=($op & RSV1_FLAG)!=0;
				$rsv2=($op & RSV2_FLAG)!=0;
				$rsv3=($op & RSV3_FLAG)!=0;
				$op&=0x0F;
				#Deflate for this message
				$do_deflate=$rsv1  && $deflate_flag;

				$masked = ($len & 0b10000000)>0;#FIN_FLAG ;
				#inital 7 bits of len
				$len&=0b01111111;
				warn "LENGTH: $len\n" if DEBUG;
				#say "op code: $op";
				for($len){
					if($_==0) {
						$hlen = 2;
						warn "NO Length payload\n" if DEBUG;
					}
					elsif($_< 126){
						$hlen = 2;
						warn "SMALL payload\n" if DEBUG;
					}
					elsif($_==126){
						# 16 bit extended payload length
						return unless length $buf > 4;
						$hlen = 4;
						my $ext = substr $buf, 2, 2;
						$len = unpack 'n', $ext;
						warn "EXTENDED payload (16bit): $len\n" if DEBUG;
					}
					elsif($_==127){

						# Extended payload (64bit)
						return unless length $buf > 10;
						$hlen = 10;
						my $ext = substr $buf, 2, 8;
						$len= unpack('Q>', $ext);
                                                ######################################
                                                # $len =                             #
                                                # $Config{ivsize} > 4                #
                                                # ? unpack('Q>', $ext)               #
                                                # : unpack('N', substr($ext, 4, 4)); #
                                                ######################################
						warn "EXTENDED payload (64bit): $len\n" if DEBUG;
					}
					else{
						#error if here
					}
				}
				#say "valid length: $len";


				if($masked){	
					#check if we have enough data 
					return unless length $buf >= ($hlen+4);
					$mask = substr($buf, $hlen, 4);
					$hlen+=4;
				}
				else{
					$mask=0;
				}

				#say "header len was $hlen";	
				substr $buf, 0, $hlen, "";
				#say "buf after header: ", unpack "H*", $buf;
				$state=STATE_BODY;
				next;
			}

			elsif($state==STATE_BODY){
				#say "Parsing body with op:" , $op;
				#do body	
				return if length $buf < $len;
				if($op == TEXT){
					#check payload can be decoded
					$mode=TEXT;
					#masked and fin
					warn "UNMASKING PAYLOAD\n" if DEBUG;
					_xor_mask_inplace(substr($buf, 0, $len), $mask);
					if($do_deflate){
						my $data;
						rawinflate \substr($buf,0,$len)=> \$data;
						$on_fragment->($self, $self->[id_], decode("UTF-8",substr $buf, 0, $len,''),$fin);
						
						#$on_message->($self, $self->[id_], decode("UTF-8",substr $buf, 0, $len,''),$fin);
					}
					else {
						$on_fragment->($self, $self->[id_], decode("UTF-8",substr $buf, 0, $len,''),$fin);
					}
					#say "buffer after body: ", unpack "H*", $buf;

				}

				elsif($op == BINARY){
					say "BINARAY FRAME";
					$mode=BINARY;
					$on_fragment->($self, $self->[id_], _xor_mask(substr($buf, 0, $len,''), $mask), $fin);
				}

				elsif($op == CONTINUATION){
						if($mode==TEXT){
							_xor_mask_inplace(substr($buf, 0, $len), $mask);
							$on_fragment->($self, $self->[id_], decode("UTF-8",substr $buf, 0, $len,''),$fin);
						}
						else {
							$on_fragment->($self, $self->[id_], _xor_mask(substr($buf, 0, $len, ''), $mask), $fin);
						}
				}
				elsif($op == PING){
					#do not change accumulating payload
					#reply directly with PONG
					say "GOT PING";
					warn "UNMASKING PAYLOAD\n" if DEBUG;
					$self->[writer_]->(FIN_FLAG|PONG, _xor_mask(substr($buf, 0, $len,''), $mask));
					substr $buf,0, $len,'';

				}
				elsif($op == PONG){
					#assumes a fin flag
					#say "GOT PONG";
					#do not change accumulating payload
					substr $buf,0, $len,'';
				}
				elsif($op == CLOSE){
					#TODO: break out reason code and description
					say "GOT CLOSE";
					_xor_mask(substr($buf, 0, $len, ''),$mask);

					#TODO: drop the session, undef any read/write subs
					$self->[pinger_]=undef;
					$self->[on_close_]->($self, $self->[id_]);
					$session->[uSAC::HTTP::Session::closeme_]=1;
					$session->[uSAC::HTTP::Session::dropper_]->();

				}
				else{
					#error in protocol. close
				}
				$state=STATE_HEADER;
				next;
			}
		}
	}

}


#To be used with middler
sub _websocket_writer {
	my $next =shift;	# This is the reference to the next item in the stack

	sub {
		#take input data, convert to frame and use normal writer?
		my ($op_flags, $payload, $cb, $arg)=@_;
		$cb//=sub {};		#if no callback provided, fire and forget
		$arg//=__SUB__;		#Use 'self' as argument if none provided
		warn "BUILDING FRAME\n" if DEBUG;

		# Head
		#say "fin is $fin";
		#say "op is $op";


		my $frame= pack "C", $op_flags;
		say "Frame ",unpack "H*",$frame if DEBUG;
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
			vec($prefix, 0, 8) = $masked ? ($len | FIN_FLAG) : $len;
			$frame .= $prefix;
		}

		# Extended payload (16bit)
		elsif ($len < 65536) {
			vec($prefix, 0, 8) = $masked ? (126 | FIN_FLAG) : 126;
			$frame .= $prefix;
			$frame .= pack 'n', $len;
		}

		# Extended payload (64bit)
		else {
			vec($prefix, 0, 8) = $masked ? (127 | FIN_FLAG) : 127;
			$frame .= $prefix;
			$frame .= pack('Q>', $len);
                        ################################################
                        # $frame .=                                    #
                        # $Config{ivsize} > 4                          #
                        # ? pack('Q>', $len)                           #
                        # : pack('NN', $len >> 32, $len & 0xFFFFFFFF); #
                        ################################################
		}

		if (DEBUG) {
			warn 'HEAD: ', unpack('B*', $frame), "\n";
			warn "OPCODE: $op_flags\n";
		}

		# Payload
		$frame .= $payload;
		if(DEBUG){

			say "FRAME TO SEND ",$frame;
			say "NEXT is : ", $next;
		}
		$next->($frame,$cb,$arg);
		return;
	}
}

#sub which links the websocket to socket stream
#
sub _make_websocket_server_writer {
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
	state $id=0;	
	my $self=[];
	$self->@[(id_, session_, maxframe_, mask_, ping_interval_, state_, on_message_, on_error_, on_close_, on_open_)]=($id++, $session, 1024**2, 0, 5, OPEN, sub {}, sub {}, sub {}, sub{});

	bless $self, $pkg;
	$session->[uSAC::HTTP::Session::rex_]=$self;	#update rex to refer to the websocket
	$session->[uSAC::HTTP::Session::closeme_]=1;	#At the end of the session close the socket

	$self->[writer_]=_make_websocket_server_writer $self, $session;	#create a writer and store in ws
	say "Created writer: ",$self->[writer_];

	#the pushed reader now has access to the writer via the session->rex
	$session->push_reader(_make_websocket_server_reader($self,$session));

	#setup ping
	$self->ping_interval($self->[ping_interval_]);

	#override dropper
	my $old_dropper=$session->[uSAC::HTTP::Session::dropper_];
	my $dropper=sub {
		$self->[pinger_]=undef;
		$self->[writer_]=sub {};
		$old_dropper->();
		say "WEBSOCKET CLOSED";
		$self->[on_close_]->();
	};
	$session->[uSAC::HTTP::Session::dropper_]=$dropper;

	return $self;
}

#called be default on fragment
sub _decode_message {
	#use current opcode and flags to aggregate fragmented messages and then call on_message
}




sub _xor_mask($$) {
	use integer;
	return $_[0] unless $_[1];
	$_[0] ^.
	(
		$_[1] x (length($_[0])/length($_[1]) )
		. substr($_[1],0,length($_[0]) % length($_[1]))
	);
}


sub _xor_mask_inplace($$) {
	return unless $_[1];
	my ($a,$b)=(length($_[0]), length($_[1]));
	$_[0] ^.=
	(
		$_[1] x ($a/$b) 
		. substr($_[1],0, $a % $b)
	);
	return
}


#message and connection
sub send_binary_message {
	my $self=splice @_,0, 1, FIN_FLAG|BINARY;
	&{$self->[writer_]};

}


#Write text message and do optional callback
sub send_text_message {
	#write as a single complete message. checks utf flag
	my $self=splice @_, 0, 1, FIN_FLAG|TEXT;
	&{$self->[writer_]};
}

sub close {
	my $self=splice @_,0, 1, FIN_FLAG|CLOSE;
	&{$self->[writer_]};
}

#getter/setters
sub on_message: lvalue {
	$_[0][on_message_];
}
sub on_fragment:lvalue {
	$_[0][on_fragment_];
}

sub on_close: lvalue {
	$_[0][on_close_];
}

sub on_error: lvalue {
	$_[0][on_error_];
}

sub on_open: lvalue {
	$_[0][on_open_];	
}
#on connect and on open are same events. 
sub on_connect: lvalue {
	$_[0][on_open_];	
}

sub ping_interval {
	my ($self, $new)=@_;
	return $self->[ping_interval_] unless defined $new;
	
	undef $self->[pinger_];
	$self->[ping_interval_]=$new;
	$self->[pinger_] = AE::timer(0, $self->[ping_interval_], sub {
			#say "Sending ping\n\n\n\n";
		$self->[ping_id_] = "hello";	
		$self->[writer_]->( FIN_FLAG | PING, $self->[ping_id_]); #no cb used->dropper defalt
		#TODO: Add client ping support? (ie masking)

	} ) if $self->[ping_interval_] > 0;
	return $self->[ping_interval_];
}


1;
