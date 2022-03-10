package uSAC::HTTP::Middleware;
use strict;
use warnings;
use Exporter 'import';
use feature qw<refaliasing say fc switch state current_sub signatures>;
no warnings "experimental";
no feature "indirect";
use uSAC::HTTP::Session;
use uSAC::HTTP::Code qw<:constants>;
use uSAC::HTTP::Header qw<:constants>;
use uSAC::HTTP::Rex;

use Time::HiRes qw<time>;
use IO::Compress::Gzip;
use Compress::Raw::Zlib;

use MIME::Base64;		
use Digest::SHA1;

use Crypt::JWT qw<decode_jwt encode_jwt>;
use Data::Dumper;
use List::Util qw<first>;
use Log::ger;




use constant LF => "\015\012";

our @EXPORT_OK=qw<
	dummy_mw 
	log_simple log_simple_in log_simple_out 
	chunked
	deflate
	gzip
	authenticate_simple
	state_simple
>;
our @EXPORT=();
our %EXPORT_TAGS=(
	"all"=>[@EXPORT_OK]
);
use uSAC::HTTP::Middler;

my @key_indexes=map {$_*2} 0..99;

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
# ===========
# Log Simple - Log basic stats to STDERR
#
sub log_simple {
	[&log_simple_in, &log_simple_out]
}

sub log_simple_in {
	my %options=@_;
	my $dump_headers=$options{dump_headers};

	my $dump_capture=$options{dump_capture};

	#Header processing sub
	sub {
		my $inner_next=shift;	#This is the next mw in the chain
		sub {
			my $time=time;
			#say "INNER LOG: ", @{^CAPTURE};
			package uSAC::HTTP::Rex {
				say STDERR "\n---->>>";
				say STDERR "Arraval time:		".$time;
				say STDERR "Host: 			$_[1][host_]";
				say STDERR "Original matched URI: 	$_[1][uri_]";
				say STDERR "Site relative URI:	$_[1][uri_stripped_]";
				say STDERR "Matched for site:	".($_[0][4][0]->id//"n/a");
				say STDERR "Hit counter:		$_[0][3]";
				say STDERR "Captures:		".join ", ",$_[1][capture_]->@* if $dump_capture;
				say STDERR Dumper $_[1]->headers if $dump_headers;
			}
			return &$inner_next;		#alway call next. this is just loggin
		}
	};
	
	#Body processing sub
	
	#Return as a array [$header, $body]
}

sub log_simple_out {
	#header processing sub
	sub {
		my $outer_next=shift;
		sub {
			say STDERR "\n<<<---";
			say STDERR "Depature time:		".time;
			say STDERR Dumper $_[3];
			return &$outer_next;
		}
	};

	#Body processing sub
	
	#Return as a array [$header, $body]
}



# =============


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
				rex_write @_, (HTTP_FORBIDDEN,{} , "Go away!");
				return;
			}
			return &$next;		#alway call next. this is just loggin
		}
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
#Last write must be an empty string
#
sub chunked{
	#"x"x1024;
	#$scratch="";

	#matcher,rex, code, headers, data,cb,arg
	my $chunked_in=
	sub {
		my $next=shift;
		
	};
	my $chunked_out=
	sub {
		my $next=shift;
		my $bypass;
		sub {
			CONFIG::log  and log_trace "Chunked Outerware";
			if($_[3]){
				$bypass=undef;#reset
				\my @headers=$_[3];
				for my $k (@key_indexes){
					last if $k >= @headers;
					($bypass= ($headers[$k]) == (HTTP_CONTENT_LENGTH)) and return &$next;
					#($bypass= $headers[$k] =~ /^@{[HTTP_CONTENT_LENGTH]}/ioaa) and return &$next;
				}
				CONFIG::log and log_debug "Chunk bypass: $bypass";
				
				#we actually have  headers and Data. this is the first call
				#Add to headers the chunked trasfer encoding
				#
				my $index=-1;
				for my $k (@key_indexes){
					last if $k>=@headers;
					$index =$k if ($headers[$k]) == (HTTP_TRANSFER_ENCODING);
					#$index =$k if $headers[$k] =~ /@{[HTTP_TRANSFER_ENCODING]}/ioaa;
				}

				if($index<0){

					push @headers, HTTP_TRANSFER_ENCODING, "chunked";
				} 
				else {
					for($headers[$index+1]){
						$_=join ", ", $_, "chunked " unless $_ =~ /chunked/;
					}
				}
			}
			return &$next if $bypass;

			my $scratch="";
			$scratch=sprintf("%02X".LF,length $_[4]).$_[4].LF if $_[4];
			$scratch.="00".LF.LF unless $_[5];
			return $next->(@_[0,1,2,3],$scratch,@_[5,6]) if $scratch;

			return &$next;

		};
	};

	[$chunked_in, $chunked_out]
}



sub deflate {
	my $in=sub {
		my $next=shift;
		sub {
			&$next;
		}
	};

	my $out=sub {
		my $next=shift;
		my $bypass;
		my $compressor=Compress::Raw::Zlib::Deflate->new(-AppendOutput=>1, -Level=>6,-ADLER32=>1);
		my $status;
		my $index;
		(sub {

			# 0	1 	2   3	    4     5
			# usac, rex, code, headers, data, cb
			\my $buf=\$_[4];

			if($_[3]){
				CONFIG::log  and log_trace "Entering deflate output";
				\my @headers=$_[3]; #Alias for easy of use and performance

				$bypass=undef; #reset

				unless($_[4]){
					#If empty or undefined body, then we disable.
					$bypass=1;
				}

				#Also disable if we are already encoded
				for my $k (@key_indexes){
					last if $k >= @headers;
					CONFIG::log  and log_trace "$headers[$k] => $headers[$k+1]";
					($bypass||= ($headers[$k]) == (HTTP_CONTENT_ENCODING)) and return &$next;
					#($bypass||= $headers[$k] =~ /^@{[HTTP_CONTENT_ENCODING]}/ioaa) and return &$next;
				}

				#Also disable if client doesn't want our services
				$bypass||=($_[1]->headers->{ACCEPT_ENCODING}//"") !~ /deflate/iaa;


				#
				# Also avoid compressing any of the following
				# TODO: add content type matching



				return &$next if $bypass;

				#Remove content length as we will rely on chunked encoding
				for my $k (@key_indexes){
					last if $k >= @headers;
					CONFIG::log and log_debug "Header testing: $headers[$k]";
					(($headers[$k]) == (HTTP_CONTENT_LENGTH)) and ($index=$k);
					#($headers[$k] =~ /^@{[HTTP_CONTENT_LENGTH]}/ioaa) and ($index=$k);
					last if defined $index;
				}

				CONFIG::log and log_debug "Content length index: $index";

				splice(@headers, $index, 2) if defined $index;
				

				#Set our encoding header
				push @headers, HTTP_CONTENT_ENCODING, "deflate";


				#Finally configure compressor	
				# reset compression context
				#
				$status=$compressor->deflateReset();
				$status == Z_OK or log_error "Could not reset deflate";
			}
			CONFIG::log and log_trace "Processing deflate content";
			# Only process if setup correctly
			#
			return &$next if $bypass;


			# Append comppressed data to the scratch when its ready
			#
			my $scratch=""; 	#new scratch each call
			$status=$compressor->deflate($buf, $scratch);
			$status == Z_OK or log_error "Error creating deflate context";


			# Push to next stage
			unless($_[5]){
				CONFIG::log and log_trace "No more data expected";
				#if no callback is provided, then this is the last write
				$status=$compressor->flush($scratch);
				$next->(@_[0,1,2,3], $scratch , @_[5,6]);
				return;

			}
			else {
				CONFIG::log and log_trace "Expecting more data";
				# more data expected
				if(length $scratch){
					#enough data to send out
					$next->(@_[0,1,2,3], $scratch , @_[5,6]);
					$_[5]->($_[6]);	#execute callback to force feed
				}
			}
		},
	)
	};
	[$in, $out];
}

sub gzip{
	my $in=sub {
		my $next=shift;
		
	};

	my $out=sub {
		my $next=shift;
		my $bypass;
                my $compressor;
		my $status;
		my $scratch="";
		my $index;
		sub {
			CONFIG::log and log_trace "Gzip out middleware";

			# 0	1 	2   3	    4     5
			# usac, rex, code, headers, data, cb
			\my $buf=\$_[4];
			if($_[3]){
				\my @headers=$_[3]; #Alias for easy of use and performance
				$bypass=undef;#reset  for reuse

				unless($_[4]){
					#If empty or undefined body, then we disable.
					$bypass=1;
				}

				$bypass||=($_[1]->headers->{ACCEPT_ENCODING}//"") !~ /gzip/iaa;

				#Also disable if we are already encoded
				for my $k (@key_indexes){
					last if $k >= @headers;
					($bypass||= $headers[$k] == HTTP_CONTENT_ENCODING) and last;
					#($bypass||= $headers[$k] =~ /^@{[HTTP_CONTENT_ENCODING]}/ioaa) and last;
				}

				return &$next if $bypass;

				#Remove content length as we will rely on chunked encoding
				for my $k (@key_indexes){
					last if $k >= @headers;
					CONFIG::log and log_debug "Header testing: $headers[$k]";
					($headers[$k] == HTTP_CONTENT_LENGTH) and ($index=$k);
					last if defined $index;
				}

				CONFIG::log and log_debug "Content length index: $index";

				splice(@headers, $index, 2) if defined $index;
				

				#Set our encoding header
				push @headers, HTTP_CONTENT_ENCODING, "gzip";



				# reset compression context
				#
				$scratch="";
				$compressor=IO::Compress::Gzip->new(\$scratch, "Append"=>1, "Level"=>1, Minimal=>1);
			}

			# Only process if setup correctly
			#
			return &$next if $bypass;


			# Append comppressed data to the scratch when its ready
			#
			my $copy=""; 	#new scratch each call
			$compressor->syswrite($buf);


			# Push to next stage
			unless($_[5]){
				#if no callback is provided, then this is the last write
				$compressor->close;
				$copy=$scratch;
				$scratch="";
				$next->(@_[0,1,2,3], $copy, @_[5,6]);
				return;

			}
			else {
				# more data expected
				if(length $scratch){
					#enough data to send out
					$copy=$scratch;
					$scratch="";
					$next->(@_[0,1,2,3], $copy, @_[5,6]);
					$_[5]->($_[6]);	#execute callback to force feed
				}
			}
		}
	};
	[$in, $out];





}


1;

__END__

=head1 NAME

uSAC::HTTP::Middleware - Common Middleware and API

=head1 API

Each component inner or outerware is a sub reference, which has captured the next sub lexically in a closure.

Linking is performed by L<Sub::Middler>  to generate a chained set of middlewares

Arguments to the Middlware are as follows:

	Matcher Rex code headers body callback arg

Aliasing to be used where possible

First call must have headers defined. If body is 'true' (non empty string), then if the middlware modifies the body, it can enable itself.
A false body indicates the body will be sent outside of this middleware chain (ie sendfile). Should be disabled.

Subsequency calls Must have headers undefined.	
	Renderer sets headers to undef (as its aliased). So using the same variable this should be automatic


The last call is indicated by not suppling a callback. Middleware which modifies the body should flush when this condition is present.

