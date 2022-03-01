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

use Time::HiRes qw<time>;
use IO::Compress::Gzip;
use Compress::Raw::Zlib;

use MIME::Base64;		
use Digest::SHA1;

use Crypt::JWT qw<decode_jwt encode_jwt>;
use Data::Dumper;
use List::Util qw<first>;

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
		sub {
			&$next;
		};
	};
	my $chunked_out=
	sub {
		my $next=shift;
		my $bypass;
		sub {

			say "Calling chunked";
			#return &$next if($_[3] and grep HTTP_TRANSFER_ENCODING eq $_, $_[3]->@*);

			if($_[3]){
				$bypass=defined first {$_[3][$_*2] =~ HTTP_CONTENT_LENGTH} 0..$_[3]->@*/2-1;
				return &$next if $bypass;
				
				#we actually have  headers and Data. this is the first call
				#Add to headers the chunked trasfer encoding
				#
				my $index=first {$_[3][$_*2] =~ HTTP_TRANSFER_ENCODING} 0..$_[3]->@*/2-1;

				if(!defined($index)){

					push $_[3]->@*, HTTP_TRANSFER_ENCODING, "chunked";
				} 
				else {
					for($_[3][$index*2+1]){
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
			say "DEFLATE IN.. bypass";
			&$next;
		}
	};

	my $out=sub {
		my $next=shift;
		my $bypass;
		my $compressor=Compress::Raw::Zlib::Deflate->new(-AppendOutput=>1, -Level=>6);
		my $status;
		my $index;
		(sub {
			say "calling deflate out";

			# 0	1 	2   3	    4     5
			# usac, rex, code, headers, data, cb
			\my $buf=\$_[4];
			if($_[3]){
				#Calling first time with headers

				# Check content negotiation
				#
				$bypass=($_[1]->headers->{ACCEPT_ENCODING}//"") !~ /deflate/;

				# Also avoid compressing any of the following
				# TODO: add content type matching


				# locate transfer encoding header if present
				#
				$bypass||=defined first {$_[3][$_] =~ HTTP_CONTENT_ENCODING} 0..$_[3]->@*/2-1;

				return &$next if $bypass;

				# Remove content length. We rely on chunked transfer
				$index=first {$_[3][$_] =~ HTTP_CONTENT_LENGTH} 0..$_[3]->@*/2-1;
				splice($_[3]->@*, $index, 2) if defined $index;
				

				push $_[3]->@*, HTTP_CONTENT_ENCODING, "deflate";
				say "HEaders after deflate", Dumper $_[3];

				# reset compression context
				#
				$status=$compressor->deflateReset();
				$status == Z_OK or say STDERR "Could not reset deflate";
			}

			# Only process if setup correctly
			#
			return &$next if $bypass;


			# Append comppressed data to the scratch when its ready
			#
			my $scratch=""; 	#new scratch each call
			$status=$compressor->deflate($buf, $scratch);
			$status == Z_OK or say STDERR "deflating error";


			# Push to next stage
			unless($_[5]){
				#if no callback is provided, then this is the last write
				$status=$compressor->flush($scratch);
				$next->(@_[0,1,2,3], $scratch , @_[5,6]);
				return;

			}
			else {
				# more data expected
				if(length $scratch){
					#enough data to send out
					$next->(@_[0,1,2,3], $scratch , @_[5,6]);
					$_[5]->($_[6]);	#execute callback to force feed
				}
			}
		},
		#TODO:
		# add chunked out only here
	)
	};
	[$in, $out];
}

sub gzip{
	my $in=sub {
		my $next=shift;
		sub {
			say "gzip IN.. bypass";
			&$next;
		}
	};

	my $out=sub {
		my $next=shift;
		my $bypass;
                my $compressor;
		my $status;
		my $scratch="";
		sub {
			say "calling gzip out";

			# 0	1 	2   3	    4     5
			# usac, rex, code, headers, data, cb
			\my $buf=\$_[4];
			if($_[3]){
				#Calling first time with headers

				# Check content negotiation
				#
				$bypass=($_[1]->headers->{ACCEPT_ENCODING}//"") !~ /gzip/;

				# Also avoid compressing any of the following
				# TODO: add content type matching


				# locate transfer encoding header if present
				#
				$bypass||=defined first {$_[3][$_] =~ HTTP_CONTENT_ENCODING} 0..$_[3]->@*/2-1;

				return &$next if $bypass;

				push $_[3]->@*, HTTP_CONTENT_ENCODING, "deflate";

				# reset compression context
				#
				$scratch="";
				$compressor=IO::Compress::Gzip->new(\$scratch, "-Level"=>-1, Minimal=>1);
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
