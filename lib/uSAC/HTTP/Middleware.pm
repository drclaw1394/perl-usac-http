package uSAC::HTTP::Middleware;
use strict;
use warnings;
use Exporter 'import';
use feature qw<refaliasing say state>;
no warnings "experimental";

#no feature "indirect";
#use uSAC::HTTP::Session;
use uSAC::HTTP::Code qw<:constants>;
use uSAC::HTTP::Header qw<:constants>;
use uSAC::HTTP::Rex;
use uSAC::HTTP::Constants;

use Time::HiRes qw<time>;


use Log::ger;
use Log::OK;





our @EXPORT_OK=qw<
	log_simple
	chunked
	authenticate_simple
	state_simple
>;
our @EXPORT=();
our %EXPORT_TAGS=(
	"all"=>[@EXPORT_OK]
);

my @key_indexes=map {$_*2} 0..99;


# ===========
# Log Simple - Log basic stats to STDERR
#
sub log_simple {
	[&log_simple_in, &log_simple_out]
}

sub log_simple_in {
  require Data::Dumper;
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
          say STDERR "Arraval initial time:		$time";
          say STDERR "Host: 			$_[1][host_]";
          say STDERR "Method:       $_[1][method_]";
          say STDERR "Original matched URI: 	$_[1][uri_]";
          say STDERR "Site relative URI:	$_[1][uri_stripped_]";
          say STDERR "Matched for site:	".($_[0][1][0]->id//"n/a");
          say STDERR "Hit counter:		$_[0][1][4]";
          say STDERR "Captures:		".join ", ",$_[1][captures_]->@* if $dump_capture;
          say STDERR "Headers:" if $dump_headers;
          say STDERR Data::Dumper::Dumper $_[1]->headers if $dump_headers;
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
  my $chunked_out=
  sub {
    my $next=shift;
    #my $bypass;
    sub {
      if($_[CODE]){

        Log::OK::TRACE  and log_trace "Middeware: Chunked Outerware";
        Log::OK::TRACE  and log_trace "Key count chunked: ". scalar keys %out_ctx;
        Log::OK::TRACE  and log_trace "Chunked: ". join " ", caller;
        #\my $bypass=\$out_ctx{$_[1]}; #access the statefull info for this instance and requst
        my $exe;
        if($_[HEADER]){
          #$bypass=undef;#reset
          \my @headers=$_[HEADER];

          (($_ eq HTTP_CONTENT_LENGTH)) and return &$next for(@headers[@key_indexes[0..@headers/2-1]]);
          $exe=1;

          Log::OK::TRACE and log_trace "Middelware: Chunked execute".($exe//"");

          #we actually have  headers and Data. this is the first call
          #Add to headers the chunked trasfer encoding
          #
          my $index;
          $_ eq HTTP_TRANSFER_ENCODING and ($index=$_+1, last)
            for @headers[@key_indexes[0..@headers/2-1]];

          unless($index){	
            push @headers, HTTP_TRANSFER_ENCODING, "chunked";

          }
          else{
            $headers[$index].=",chunked";

          }
          $ctx=$exe;
          $out_ctx{$_[REX]}=$ctx if $_[CB]; #save context if multishot
          #no need to save is single shot
        }

        if($ctx//=$out_ctx{$_[REX]}){
          #Process 
          Log::OK::TRACE and log_trace join ", ",caller;

          Log::OK::TRACE and log_trace "Chunked: Testing for context";

          Log::OK::TRACE and log_trace "DOING CHUNKS";

          my $scratch=sprintf("%02X".CRLF,length $_[PAYLOAD]).$_[PAYLOAD].CRLF if $_[PAYLOAD];

          unless($_[CB]){
            $scratch.="00".CRLF.CRLF;
            delete $out_ctx{$_[REX]} unless $_[HEADER];	#Last call, delete
          }

          #$next->(@_[0,1,2,3],$scratch,@_[5,6]);# if $scratch;
          $_[PAYLOAD]=$scratch;
          &$next;
        }
        else {
          #nothing to process
          &$next 
        }
      }
      else{
        #Error condition. Reset stack
        Log::OK::TRACE  and log_trace "Middeware: Chunked Passing on error condition";
        delete $out_ctx{$_[REX]};
        &$next;
      }
    };
  };

  [$chunked_in, $chunked_out]
}
1;
