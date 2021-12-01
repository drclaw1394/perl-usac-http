package uSAC::HTTP::Middleware;
use strict;
use warnings;
use Exporter 'import';
use feature qw<refaliasing say switch state current_sub signatures>;
no warnings "experimental";
no feature "indirect";
use uSAC::HTTP::Session;
use uSAC::HTTP::Cookie qw<:all>;
use uSAC::HTTP::Code qw<:constants>;
use uSAC::HTTP::Header qw<:constants>;
use uSAC::HTTP::Rex;
use uSAC::HTTP::Cookie;

use IO::Compress::Gzip;
use Compress::Raw::Zlib;

use MIME::Base64;		
use Digest::SHA1;

use Crypt::JWT qw<decode_jwt encode_jwt>;

use constant LF => "\015\012";

our @EXPORT_OK=qw<dummy_mw log_simple authenticate_simple state_simple make_chunked_writer make_chunked_deflate_writer>;
our @EXPORT=();
our %EXPORT_TAGS=(
	"all"=>[@EXPORT_OK]
);
use uSAC::HTTP::Middler;
#INCOMMING REX PROCESSING
#
sub dummy_mw{

	#No configuration used in this logger, so reuse the same sub for each call
	state $sub=sub {
		my $inner_next=shift;	#This is the next mw in the chain
		my $outer_next=shift;
		(
			sub {
				return &$inner_next;	
			},

			sub {
				return &$outer_next;
			}
		)
	};
	$sub;
}

#log to STDERR
sub log_simple {

	#No configuration used in this logger, so reuse the same sub for each call
	state $sub=sub {
		my $inner_next=shift;	#This is the next mw in the chain
		my $outer_next=shift;
		(
			sub {
				say STDERR "\n";
				say STDERR time;
				say STDERR " Host: 		$_[1][uSAC::HTTP::Rex::host_]";
				say STDERR " Original URI: 	$_[1][uSAC::HTTP::Rex::uri_]";
				say STDERR " Matcher URI:	$_[1][uSAC::HTTP::Rex::uri_stripped_]";
				say STDERR " Hit counter:		", $_[0][3];
				return &$inner_next;		#alway call next. this is just loggin
			},
			sub {
				say STDERR "\n";
				say STDERR time;
				say STDERR " Logging on the way out";
				say STDERR " Renered";
				return &$outer_next;
			}
		)
	};
	$sub;
}


sub authenticate_simple{
	my %options=@_;
	#cookie name to use 
	#create a hash to store session ids
	#
	sub {
		my $next=shift;
		sub {
			#this sub input is line, and rex
			my $rex=$_[1];
			my $cookies=$rex->cookies;
			say "checking cookies";
			#check that cookie value is found and valid in hash
			unless($cookies->{test}){
				say "invalid test variable... return forbidden";
				rex_reply_simple @_, (HTTP_FORBIDDEN,[] , "Go away!");
				return;
			}

			return &$next;		#alway call next. this is just loggin
		}
	}
}

#configure basic session management
sub state_simple {
	#given a hash ref to store the state
	state $defualt_store={};
	my %options=@_;
	my $states=$options{store}//$defualt_store;
	my $state_cb=$options{on_new}//sub {{new=>1}};
	sub {
		my $inner_next=shift;
		my $outer_next=shift;
		(
			#input sub
			sub {
				state $i;
				my $rex=$_[1];
				my $state_key;
				my $state;
				$state_key=$rex->cookies->{USAC_STATE_ID};	
				if($state_key){
					$state=$states->{$state_key};
					#existing state
					#say "EXISTING STATE";
				}
				else {
					#create a new state
					$state=&$state_cb;
					#create the state_key
					unless ($state->{key}){	
						$state->{key}= unpack "H*", Digest::SHA1::sha1(time+$i++)
					}
					$states->{$state->{key}}=$state;
				}

				#set the state for rex
				$rex->state($state);
				#say Dumper $state;
				&$inner_next;
			},

			sub {
				my $rex=$_[1];
				#Add Set cookie to the headers, if state is defined
				if(my $state=$rex->state){
                                       push $_[3]->@*,
				       #[DUMMY=>"HEADER"]
                                        [HTTP_SET_COOKIE,
                                                usac_new_cookie(USAC_STATE_ID=>$state->{key})
                                                ->serialize_set_cookie
                                        ];
				}
				#say "setting cookie";
				&$outer_next;
			}
		)
	}
}

sub state_jwt {
	my %options=@_;
	my $state_cb=$options{on_new}//sub {{new=>1}};
	sub {
		my $inner_next=shift;
		my $outer_next=shift;
		(
			#input sub
			sub ($matcher, $rex){
				&$inner_next;
			},

			sub {
				&$outer_next;
			}
		)
	}
}

sub http2_upgrade {
	my %options=@_;
	sub {
		my $inner_next=shift;
		my $outer_next=shift;
		(
				sub {
					#check for h2 and h2c header.
					#If h2c is present, send switching protocols
					#change the session reader to http2
					#change writer to http2
					#then let the middleware continue (ie call next)

				},
				sub {
					#outgoing really does need to 	anything
				}
		);
	}
}


#DEFAULT END POINT HANDLER
#


#TRANFER ENCODINGS OUTPUTS
#
#Takes input and makes chunks and writes to next
sub chunked{
	my $next=shift;
	my $scratch="";
	#"x"x1024;
	#$scratch="";

	#data,cb,arg
	sub {
		$_[2]//= __SUB__ ;		#argument to callback is self unless one is provided
		return &$next unless defined $_[0];	#reset stack if requested. pass it on
		$scratch=sprintf("%02X".LF,length $_[0]).$_[0].LF;
		$scratch.="0000".LF.LF unless $_[1];
		#say length $scratch;
		#say caller;
		shift;
		$next->($scratch, @_);
	}
}

my $sub=sub{};
sub chunked_2{
	my $next=shift;
	my $scratch="";

	sub {
		$_[2]//= __SUB__ ;		#argument to callback is self unless one is provided
		return &$next unless defined $_[0];	#reset stack if requested. pass it on
		$next->(sprintf("%02X".LF,length $_[0]),$sub,1);
		$next->($_[0],$sub,1);#->($scratch, @_);
		#$_[0].=LF;
		#$scratch.="00".LF.LF unless $_[1];
		shift;
		$_[0]?$next->(LF,@_):$next->(LF."00".LF.LF,@_);
	}
}

sub gzip {
	my $next=shift;
	my $scratch="";
	my $compressor;
	sub {

		my $cb=$_[1];
		unless(defined $_[0]){
			#reset
			$compressor->close if $compressor;
			return $next->(undef,$cb);
		}
		\my $buf=\$_[0];

		$scratch="";
		unless($compressor){
			#say "Creating new compressor";
			$scratch="";
			$compressor=IO::Compress::Gzip->new(\$scratch, "-Level"=>-1, Minimal=>1);
		}
		if(length $buf ==0){
			#say "End of data received";
			$compressor->close;
			$compressor=undef;
			$next->($scratch,sub {
					#pass on done to next
					$next->("",$cb);
			});
		}
		else{
			#say "data received";
			$compressor->syswrite($buf);
			if(length $scratch){
				#say "sending scratch";
				$next->($scratch,$cb);
			}
			else {
				#say "no new  data";
				#trigger upstream for more
				$cb->(1);
			}
		}

	}
}

sub deflate {
	my $next=shift;
	my $scratch="";
	my $compressor;
	my $status;
	$compressor=Compress::Raw::Zlib::Deflate->new(-AppendOutput=>1, -Level=>6);
	$scratch="";
	sub {
		my $cb=$_[1];
		unless(defined $_[0]){
			#reset
			#$compressor->close if $compressor;
			return $next->(undef,$cb);
		}

		\my $buf=\$_[0];


		if(length $buf ==0){
			#say "End of data received";
			$status=$compressor->flush($scratch);
			say "Status of flush: $status";
			say " scratch length: ", length $scratch;
			#$compressor=undef;
			$next->($scratch,sub {
					#pass on done to next
					$scratch="";
					$status=$compressor->deflateReset();
					say "Status of deflateReset: $status";
					$status == Z_OK or say "this isn;t good";
					$next->("",$cb);
			});
		}
		else{
			say "data received, ", length $buf;
			$status=$compressor->deflate($buf, $scratch);
			say "Status of deflat: $status";
			$status == Z_OK or say "this isn;t good";
			if(length $scratch){
				#say "sending scratch";
				$next->($scratch,$cb);
			}
			else {
				#say "no new  data";
				#trigger upstream for more
				$cb->(1);
			}
		}

	}
}
#returns a stack entry point which will write set of input data as a chunk to ouput
sub make_chunked_deflate_writer {
	my $session=shift;
	#create a chunked sub
	#and link to the writer of the session
	my ($entrypoint,$stack)=uSAC::HTTP::Middler->new()
	->register(\&uSAC::HTTP::Middleware::deflate)
	->register(\&uSAC::HTTP::Middleware::chunked)
	->link($session->[uSAC::HTTP::Session::write_]);	#this could be a normal socket writer, orssl type
	return $entrypoint;
}

#returns a stack entry point which will write set of input data as a chunk to ouput
sub make_chunked_writer {
	my $session=shift;
	#create a chunked sub
	#and link to the writer of the session
	my ($entrypoint,$stack)=uSAC::HTTP::Middler->new()
	->register(\&uSAC::HTTP::Middleware::chunked)
	->link($session->[uSAC::HTTP::Session::write_]);	#this could be a normal socket writer, orssl type
	return $entrypoint;
}

1;
