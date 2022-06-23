package uSAC::HTTP::Middleware;
use strict;
use warnings;
use Exporter 'import';
use feature qw<refaliasing say fc switch state current_sub signatures>;
no warnings "experimental";
#no feature "indirect";
use uSAC::HTTP::Session;
use uSAC::HTTP::Code qw<:constants>;
use uSAC::HTTP::Header qw<:constants>;
use uSAC::HTTP::Rex;

use Time::HiRes qw<time>;
use IO::Compress::Gzip;
use IO::Compress::Gzip::Constants;
use Compress::Raw::Zlib;


use MIME::Base64;		
use Digest::SHA1;

use Crypt::JWT qw<decode_jwt encode_jwt>;
use Data::Dumper;
use List::Util qw<first>;
use Log::ger;
use Log::OK;




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
			package uSAC::HTTP::Rex {
				say STDERR "\n---->>>";
				say STDERR "Arraval time:		".$time;
				say STDERR "Host: 			$_[1][host_]";
				say STDERR "Original matched URI: 	$_[1][uri_]";
				say STDERR "Site relative URI:	$_[1][uri_stripped_]";
				say STDERR "Matched for site:	".($_[0][1][0]->id//"n/a");
				say STDERR "Hit counter:		$_[0][1][4]";
				say STDERR "Captures:		".join ", ",$_[1][captures_]->@* if $dump_capture;
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
			#matcher, rex, code, header, body, cb, arg
			#only log on complete responses
			unless($_[5]){
				say STDERR "\n<<<---";
				say STDERR "Depature time:		".time;
			}
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
			#sub ($matcher, $rex){
			sub {
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

	my %out_ctx;
	my $ctx;
	my @hindexes;
	my $chunked_out=
	sub {
		my $next=shift;
		#my $bypass;
		sub {
			Log::OK::TRACE  and log_trace "Middeware: Chunked Outerware";
			Log::OK::TRACE  and log_trace "Key count chunked: ". scalar keys %out_ctx;
			Log::OK::TRACE  and log_trace "Chunked: ". join " ", caller;
			#\my $bypass=\$out_ctx{$_[1]}; #access the statefull info for this instance and requst
			my $exe;

			if($_[3]){
				#$bypass=undef;#reset

				\my @headers=$_[3];
				@hindexes=@key_indexes[0..@headers/2-1];
				for(@hindexes){
					#last if $_ >=@headers;

					(($headers[$_] eq HTTP_CONTENT_LENGTH)) and return &$next;
				}
				$exe=1;

				Log::OK::TRACE and log_trace "Middelware: Chunked execute".($exe//"");
				
				#we actually have  headers and Data. this is the first call
				#Add to headers the chunked trasfer encoding
				#
				my $index;
				for(@hindexes){
						#last if $_ >=@headers;
					$index=$_+1  and last if ($headers[$_] eq HTTP_TRANSFER_ENCODING);
				}
				unless($index){	
					push @headers, HTTP_TRANSFER_ENCODING, "chunked";

				}
				else{
					$headers[$index].=",chunked";

				}
				$ctx=$exe;
				$out_ctx{$_[1]}=$ctx if $_[5]; #save context if multishot
								#no need to save is single shot
			}
			#If this is the first call, $ctx will already be set by
			#the time we get here. So no need to read from hash

			$ctx//=$out_ctx{$_[1]};
			Log::OK::TRACE and log_trace join ", ",caller;

			Log::OK::TRACE and log_trace "Chunked: Testing for context";
			return &$next unless $ctx;

			Log::OK::TRACE and log_trace "DOING CHUNKS";

			my $scratch="";
			$scratch=sprintf("%02X".LF,length $_[4]).$_[4].LF if $_[4];

			unless($_[5]){
				$scratch.="00".LF.LF;
				delete $out_ctx{$_[1]} unless $_[3];	#Last call, delete
									#only when headers
									#are not present
									#(multicall)
			}

			return $next->(@_[0,1,2,3],$scratch,@_[5,6]);# if $scratch;

			#return &$next;

		};
	};

	[$chunked_in, $chunked_out]
}



sub deflate {
	my $in=sub {
		my $next=shift;
		$next;
	};

	state @deflate_pool;
	my %out_ctx; #stores bypass and  compressor
	my $ctx;
	my $dummy=sub{};
	my $out=sub {
		my $next=shift;
		my $status;
		my $index;
		(sub {
		
			

			Log::OK::TRACE and log_debug "Input data length: ".length  $_[4];
			# 0	1 	2   3	    4     5
			# usac, rex, code, headers, data, cb
			\my $buf=\$_[4];
			#Compress::Raw::Zlib::Deflate->new(-AppendOutput=>1, -Level=>6,-ADLER32=>1)
			Log::OK::TRACE and log_debug "Context count: ".scalar keys %out_ctx;
			Log::OK::TRACE and log_debug "Compressor pool: ".scalar @deflate_pool;

			Log::OK::TRACE  and log_trace "doing deflate";
			my $exe;
			if($_[3]){
				Log::OK::TRACE and log_debug "Deflate: in header processing";
				\my @headers=$_[3]; #Alias for easy of use and performance
				#$ctx->[0]=undef;#reset  for reuse

				#if this is a one shot write then we don't need to store a context
				#
                                #########################################################
                                # unless($_[4]){                                        #
                                #         #If empty or undefined body, then we disable. #
                                #         $exe=0;                                       #
                                # }                                                     #
                                #########################################################
				Log::OK::TRACE and log_trace "deflate: looking for accept";
				Log::OK::TRACE and log_trace "delfate: Incoming accept_encoding: ".Dumper $_[1]->headers;

				($exe=($_[1]->headers->{ACCEPT_ENCODING}//"") !~ /deflate/iaa) and return &$next;
				#unless $exe; #bypass is default

				#Also disable if we are already encoded
				$exe=1;
				for my $k (@key_indexes){
					last if $k >= @headers;
					Log::OK::TRACE and log_trace "Deflate: Testing header: $headers[$k]";
					($exe = undef or last )if $headers[$k] eq HTTP_CONTENT_ENCODING;
				}
				
				Log::OK::TRACE  and log_trace "exe ". $exe; 
				Log::OK::TRACE  and log_trace "Single shot: ". !$_[5];

				$ctx=$exe;
				#$out_ctx{$_[1]}=$ctx if $_[5]; #save context if more to come
						

				return &$next unless $exe; #bypass is default
				
				Log::OK::TRACE  and log_trace "No bypass in headers";

				#Remove content length as we will rely on chunked encoding
				$index=undef;
				for my $k (@key_indexes){
					last if $k >= @headers;
					Log::OK::TRACE and log_debug "Header testing: $headers[$k]";
					if($headers[$k] eq HTTP_CONTENT_LENGTH){$index=$k; last};
					#last if defined $index;
				}

				Log::OK::TRACE and log_debug "Content length index: $index";

				splice(@headers, $index, 2) if defined $index;
				

				#Set our encoding header
				push @headers, HTTP_CONTENT_ENCODING, "deflate";


				unless($_[5]){
					# no callback...single shot	
					#
					#
					#TODO: Compress::Zlib->memGzip is how to do
					#gzip and deflate and remove some overheads
					#
					$ctx=pop(@deflate_pool)//Compress::Raw::Zlib::Deflate->new(-AppendOutput=>1, -Level=>6,-ADLER32=>1);

					Log::OK::TRACE and log_trace "single shot";
					my $scratch=""; 	#new scratch each call
					my $status=$ctx->deflate($buf, $scratch);
					$status == Z_OK or log_error "Error creating deflate context";
					$status=$ctx->flush($scratch);
					$ctx->deflateReset;
					Log::OK::TRACE and log_debug "about to push for single shot";
					push @deflate_pool, $ctx;
					$next->(@_[0,1,2,3], $scratch, @_[5,6]);
					return;
					
				}
				else{
					#multiple calls required so setup context
					my $scratch="";
					$ctx=pop(@deflate_pool)//Compress::Raw::Zlib::Deflate->new(-AppendOutput=>1, -Level=>6,-ADLER32=>1);
					Log::OK::TRACE and log_trace "Multicalls required $_[1]";
					$out_ctx{$_[1]}=$ctx;

					Log::OK::TRACE and log_trace Dumper $out_ctx{$_[1]};

				}
			}
			Log::OK::TRACE and log_trace "Doing body";
			Log::OK::TRACE and log_trace "Processing deflate content";
			# Only process if setup correctly
			#
			Log::OK::TRACE and log_trace $_[1];

			$ctx//=$out_ctx{$_[1]};

			Log::OK::TRACE and log_trace Dumper $ctx;

			return &$next unless $ctx;


			# Append comppressed data to the scratch when its ready
			#
			my $scratch=""; 	#new scratch each call
			$status=$ctx->deflate($buf, $scratch);
			$status == Z_OK or log_error "Error creating deflate context";


			# Push to next stage
			unless($_[5]){
				Log::OK::TRACE and log_debug "No more data expected";
				#if no callback is provided, then this is the last write
				$status=$ctx->flush($scratch);
				delete $out_ctx{$_[1]};

				$ctx->deflateReset;
				Log::OK::TRACE and log_debug "about to push for multicall";
				push @deflate_pool, $ctx;
				Log::OK::TRACE and log_trace "delete...".scalar keys %out_ctx;

				$next->(@_[0,1,2,3], $scratch, @_[5,6]);
				return;

			}
			else {
				Log::OK::TRACE and log_debug "Expecting more data";
				# more data expected
				if(length $scratch){
					#enough data to send out
					$next->(@_[0,1,2,3], $scratch,$dummy);# @_[5,6]);
					$_[5]->($_[6]);	#execute callback to force feed
				}
			}
		},
	)
	};
	[$in, $out];
}

use constant FLAG_APPEND             => 1 ;
use constant FLAG_CRC                => 2 ;
sub gzip{
	my $in=sub {
		my $next=shift;
		$next;
	};

	state @deflate_pool;
	my %out_ctx; #stores bypass and  compressor
	my $ctx;
	my $dummy=sub{};
	my $out=sub {
		my $next=shift;
		my $status;
		my $index;
		(sub {
		
			

			Log::OK::TRACE and log_debug "Input data length: ".length  $_[4];
			# 0	1 	2   3	    4     5
			# usac, rex, code, headers, data, cb
			\my $buf=\$_[4];
			#Compress::Raw::Zlib::Deflate->new(-AppendOutput=>1, -Level=>6,-ADLER32=>1)
			Log::OK::TRACE and log_debug "Context count: ".scalar keys %out_ctx;
			Log::OK::TRACE and log_debug "Compressor pool: ".scalar @deflate_pool;

			Log::OK::TRACE  and log_trace "doing deflate";
			my $exe;
			if($_[3]){
				Log::OK::TRACE and log_debug "gzipin header processing";
				\my @headers=$_[3]; #Alias for easy of use and performance
				Log::OK::TRACE and log_trace "gzip: looking for accept";
				Log::OK::TRACE and log_trace "gzip: Incoming accept_encoding: ".Dumper $_[1]->headers;

				($exe=($_[1]->headers->{ACCEPT_ENCODING}//"") !~ /gzip/iaa) and return &$next;
				#unless $exe; #bypass is default

				#Also disable if we are already encoded
				$exe=1;
				for my $k (@key_indexes){
					last if $k >= @headers;
					Log::OK::TRACE and log_trace "gzip: Testing header: $headers[$k]";
					($exe = undef or last )if $headers[$k] eq HTTP_CONTENT_ENCODING;
				}
				
				Log::OK::TRACE  and log_trace "exe ". $exe; 
				Log::OK::TRACE  and log_trace "Single shot: ". !$_[5];

				$ctx=$exe;
				#$out_ctx{$_[1]}=$ctx if $_[5]; #save context if more to come
						

				return &$next unless $exe; #bypass is default
				
				Log::OK::TRACE  and log_trace "No bypass in headers";

				#Remove content length as we will rely on chunked encoding
				$index=undef;
				for my $k (@key_indexes){
					last if $k >= @headers;
					Log::OK::TRACE and log_debug "Header testing: $headers[$k]";
					if($headers[$k] eq HTTP_CONTENT_LENGTH){$index=$k; last};
					#last if defined $index;
				}

				Log::OK::TRACE and log_debug "Content length index: $index";

				splice(@headers, $index, 2) if defined $index;
				

				#Set our encoding header
				push @headers, HTTP_CONTENT_ENCODING, "gzip";


				unless($_[5]){
					# no callback...single shot	
					#
					#
					#TODO: Compress::Zlib->memGzip is how to do
					#gzip and deflate and remove some overheads
					#
					$ctx=pop(@deflate_pool)//Compress::Raw::Zlib::_deflateInit(FLAG_APPEND|FLAG_CRC,
                                           Z_BEST_COMPRESSION,
                                           Z_DEFLATED,
                                           -MAX_WBITS(),
                                           MAX_MEM_LEVEL,
                                           Z_DEFAULT_STRATEGY,
                                           4096,
                                           '');
				   #Compress::Raw::Zlib::Deflate->new(-AppendOutput=>1, -Level=>6,-ADLER32=>1);

					Log::OK::TRACE and log_trace "single shot";
					my $scratch=IO::Compress::Gzip::Constants::GZIP_MINIMUM_HEADER;
					my $status=$ctx->deflate($buf, $scratch);
					$status == Z_OK or log_error "Error creating deflate context";
					$status=$ctx->flush($scratch);

					$scratch.=pack("V V", $ctx->crc32(), $ctx->total_in());

					$ctx->deflateReset;
					Log::OK::TRACE and log_debug "about to push for single shot";
					push @deflate_pool, $ctx;
					$next->(@_[0,1,2,3], $scratch, @_[5,6]);
					return;
					
				}
				else{
					#multiple calls required so setup context
					$ctx=pop(@deflate_pool)//Compress::Raw::Zlib::_deflateInit(FLAG_APPEND|FLAG_CRC,
                                           Z_BEST_COMPRESSION,
                                           Z_DEFLATED,
                                           -MAX_WBITS(),
                                           MAX_MEM_LEVEL,
                                           Z_DEFAULT_STRATEGY,
                                           4096,
                                           '');
						#$ctx=pop(@deflate_pool)//Compress::Raw::Zlib::Deflate->new(-AppendOutput=>1, -Level=>6,-ADLER32=>1);
					Log::OK::TRACE and log_trace "Multicalls required $_[1]";
					$out_ctx{$_[1]}=$ctx;

					Log::OK::TRACE and log_trace Dumper $out_ctx{$_[1]};

				}
			}

			Log::OK::TRACE and log_trace "Doing body";
			Log::OK::TRACE and log_trace "Processing deflate content";
			# Only process if setup correctly
			#
			Log::OK::TRACE and log_trace $_[1];

			$ctx//=$out_ctx{$_[1]};

			Log::OK::TRACE and log_trace Dumper $ctx;

			return &$next unless $ctx;


			# Append comppressed data to the scratch when its ready
			#
			my $scratch=""; 	#new scratch each call

			$scratch=IO::Compress::Gzip::Constants::GZIP_MINIMUM_HEADER if $_[3];

			$status=$ctx->deflate($buf, $scratch);
			$status == Z_OK or log_error "Error creating deflate context";


			# Push to next stage
			unless($_[5]){
				Log::OK::TRACE and log_debug "No more data expected";
				#if no callback is provided, then this is the last write
				$status=$ctx->flush($scratch);
				$scratch.=pack("V V", $ctx->crc32(), $ctx->total_in());

				delete $out_ctx{$_[1]};

				$ctx->deflateReset;
				Log::OK::TRACE and log_debug "about to push for multicall";
				push @deflate_pool, $ctx;
				Log::OK::TRACE and log_trace "delete...".scalar keys %out_ctx;

				$next->(@_[0,1,2,3], $scratch, @_[5,6]);
				return;

			}
			else {
				Log::OK::TRACE and log_debug "Expecting more data";
				# more data expected
				if(length $scratch){
					#enough data to send out
					$next->(@_[0,1,2,3], $scratch,$dummy);# @_[5,6]);
					$_[5]->($_[6]);	#execute callback to force feed
				}
			}
		},
	)
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

