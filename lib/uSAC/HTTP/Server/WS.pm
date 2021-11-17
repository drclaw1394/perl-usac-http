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

use constant DEBUG => 0;


use enum ( "writer_=0" ,qw<maxframe_ mask_ ping_interval_ ping_id_ pinger_ state_ on_message_ on_close_ on_error_ session_>);

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


use constant {
		FIN_FLAG =>0b10000000,
		RSV1_FLAG=>0b01000000,
		RSV2_FLAG=>0b00100000,
		RSV3_FLAG=>0b00010000,
	};





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
	my $writer=$rex->[uSAC::HTTP::Rex::write_];

	my ($fin, $rsv1, $rsv2, $rsv3,$op, $mask, $len);
	my $head;
	my $masked;
	my $payload="";
	my $hlen;
	my $mode;
	\my $on_fragment=\$self->[on_message_];#$session->[uSAC::HTTP::Session::reader_cb_];
	say "ON FRAGMENT: ", $on_fragment;
	sub {
		say "IN WS READER";
		#do the frame parsing here
		say $buf;
		while( length $buf> 2){
			#return if length $buf < 2;	#do
			my $head = substr $buf, 0, 2;
			$fin  = (vec($head, 0, 8) & FIN_FLAG) == FIN_FLAG ? 1 : 0;
			$rsv1 = (vec($head, 0, 8) & 0b01000000) == 0b01000000 ? 1 : 0;
			#warn "RSV1: $rsv1\n" if DEBUG;
			$rsv2 = (vec($head, 0, 8) & 0b00100000) == 0b00100000 ? 1 : 0;
			#warn "RSV2: $rsv2\n" if DEBUG;
			$rsv3 = (vec($head, 0, 8) & 0b00010000) == 0b00010000 ? 1 : 0;
			#warn "RSV3: $rsv3\n" if DEBUG;

			# Opcode
			$op = vec($head, 0, 8) & 0b00001111;

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
			$masked = vec($head, 1, 8) & FIN_FLAG ;
			return if length $buf < ($len + $hlen + ($masked ? 4 : 0));

			#substr $buf, 0, $hlen, '';	#clear the header
			


			$len += 4 if $masked;
			return if length $buf < $len;
			#$payload = $len ? substr($buf, 0, $len, '') : '';

			#$payload="" if $op == TEXT or $op == BINARY;

			if($op == TEXT){
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
			elsif($op == BINARY){
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
			elsif($op == CONTINUATION){

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
			elsif($op == PING){
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
			elsif($op == PONG){
				#do not change accumulating payload
				say "GOT PONG";
				substr $buf,0, $hlen+$len,'';
				next;
			}
			elsif($op == PING){
				say "GOT PING";

				substr $buf,0, $hlen+$len,'';
				next;
			}
			elsif($op == CLOSE){
				say "GOT CLOSE";
				substr $buf,0, $hlen+$len,'';
				#TODO: drop the session, undef any read/write subs
				$self->[pinger_]=undef;
				$self->[on_close_]->();
				$session->[uSAC::HTTP::Session::dropper_]->(1);
				#$session->drop;

			}
			else{
				#error in protocol. close
			}
		}
	}

}

sub _websocket_writer {
	my $next =shift;	# This is the reference to the next item in the stack

	sub {
		#take input data, convert to frame and use normal writer?
		#my ($fin, $rsv1, $rsv2, $rsv3, $op, $payload, $cb,$arg) = @_;
		my ($op_flags, $payload, $cb, $arg)=@_;
		$cb//=sub {};		#if no callback provided, fire and forget
		$arg//=__SUB__;		#Use 'self' as argument if none provided
		warn "BUILDING FRAME\n" if DEBUG;

		# Head
		my $frame = 0b00000000;
		#say "fin is $fin";
		#say "op is $op";


		$frame= pack "C", $op_flags;
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
			$frame .=
			$Config{ivsize} > 4
			? pack('Q>', $len)
			: pack('NN', $len >> 32, $len & 0xFFFFFFFF);
		}

		if (DEBUG) {
			warn 'HEAD: ', unpack('B*', $frame), "\n";
			warn "OPCODE: $op_flags\n";
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
	
	#my %args = @_;
        #############################################################
        # my $h = $args{h};                                         #
        # my $self = bless {                                        #
        #         #on_fragment=>$on_fragment,                       #
        #         session=>$session,                                #
        #         maxframe      => 1024*1024,                       #
        #         mask          => 0,                               #
        #         ping_interval => 2,                               #
        #         state         => OPEN,                            #
        #         on_message_ => sub {say "Default on message"},    #
        #         on_error_       => sub { say "Default on error"}, #
        #         on_close_       => sub { say "Default on close"}, #
        #                                                           #
        #         %args,                                            #
        # },                                                        #
        #############################################################
	my $self=[];
	$self->[session_, maxframe_, mask_, ping_interval_, state_, on_message_, on_error_, on_close_]=($session, 1024**2, 0, 2, OPEN, sub { say "Default on message"}, sub {say "default on error"}, sub {say "Default on close"});

	bless $self, $pkg;
	$session->[uSAC::HTTP::Session::rex_]=$self;	#update rex to refer to the websocket
	$session->[uSAC::HTTP::Session::closeme_]=1;	#At the end of the session close the socket

	$self->[writer_]=make_websocket_server_writer $self, $session;	#create a writer and store in ws
	say "Created writer: ",$self->[writer_];

	#the pushed reader now has access to the writer via the session->rex
	$session->[uSAC::HTTP::Session::read_]=make_websocket_server_reader($self,$session);
	$session->[uSAC::HTTP::Session::reader_cb_]=undef;

	#setup ping
	$self->[pinger_] = AE::timer 0,$self->[ping_interval_], sub {
		say "Sending ping";
		$self->[ping_id_] = "hello";	
		$self->[writer_]->( FIN_FLAG | PING, $self->[ping_id_]); #no cb used->dropper defalt
		#$self->[writer_]->( 1,0,0,0, PING, $self->[ping_id_]); #no cb used->dropper defalt

	} if $self->[ping_interval_] > 0;

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




sub _xor_mask($$) {
	use integer;
	$_[0] ^
	(
		$_[1] x (length($_[0])/length($_[1]) )
		. substr($_[1],0,length($_[0]) % length($_[1]))
	);
}

#does an inplace xor
sub _xor_with_mask {
		
}


#message and connection
sub write_binary_message {
	$_[0]->[writer_]->(FIN_FLAG | BINARY, $_[1]);

}

sub write_text_message {
	#write as a single complete message. checks utf flag
	$_[0]->[writer_]->(FIN_FLAG|TEXT, $_[1]);
}

sub close {
	#write a close message
	$_[0]->[writer_]->(FIN_FLAG|CLOSE,"");
}

#getter/setters
sub on_message {
	$_[0][on_message_]=$_[1]//$_[0][on_message_];
}
sub on_close {
	$_[0][on_close_]=$_[1]//$_[0][on_close_];
}
sub on_error {
	$_[0][on_error_]=$_[1]//$_[0][on_error_];
}


1;
