#
# IMPORTANT 
#
# Middleware must pass 6 argument along the chain
#
#   route, rex, code, header, payload, cb
#
# As most of the uSAC api utiliseds the @_ array, it is very important to keep the count correct.
#
# route and rex must alway be defined and set by the parser at the start of the chain
# 
# code can be any non zero, valid http code for normal processing (a true value)
# when code is false, it triggers a stack reset all the way down to the output writer
#
# header must be a has ref, even an empty one, for the start of a request. Middleware
# further down the line will set this to undef when it has started its 'accumualted' output.
# ie the serializer will do this, on the fly zip, gzip compression will also do this.
#
# payload is the data to send to the next middleware component. It is normally
# string content, but does not have to be
#
# callback is the sub ref to call when the 'accumulator' has processed the data
# chunk. When it is undef, in indicates the upstream middleware does not need
# notifificaiton and has finished. This the instruct the acculuator to
# performan any finishing work, and potentailly call futher middleware
#
# It is also important that each of the above are lvalues, not constants. This
# is because middleware stages might write to the (aliased) variable which will
# continue to be used for subsequent middleware. Of course you can compy the
# arguments however that causes a performance hit
#
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

  my $dump_capture=$options{dump_captures};
  my $sort_headers=$options{sort};
	#Header processing sub
	sub {
		my $inner_next=shift;	#This is the next mw in the chain
		sub {

      return &$inner_next unless $_[CODE] and $_[HEADER];
			my $time=time;

      package uSAC::HTTP::Rex {
          say STDERR "\n---->>>";
          say STDERR "Arraval initial time:		$time";
          say STDERR "Host: 			$_[1][host_]";
          say STDERR "Method:       $_[1][method_]";
          say STDERR "Original matched URI: 	$_[1][uri_raw_]";
          say STDERR "Site relative URI:	$_[1][uri_stripped_]";
          say STDERR "Matched for site:	".($_[0][1][0]->id//"n/a");
          say STDERR "Hit counter:		$_[0][1][4]";
          say STDERR "Captures:\n".join "\n",$_[1][captures_]->@* if $dump_capture;
          if($dump_headers){
            say STDERR "Headers:\n" if $dump_headers;
            my $headers=$_[1]->headers;
            my $out="";
            for my($k, $v)(%$headers){
              $out.="$k: $v\n"; 
            }
            say STDERR $out;
            #say STDERR Data::Dumper::Dumper $_[1]->headers if $dump_headers;
          }
			}
			&$inner_next;		#alway call next. this is just logging
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
      return &$outer_next unless $_[CODE] and $_[HEADER];

      say STDERR "\n<<<---";
      say STDERR "Depature time:		".time;

			&$outer_next;
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


############################################################################################################
# #TRANFER ENCODINGS OUTPUTS                                                                               #
# #                                                                                                        #
# #Takes input and makes chunks and writes to next                                                         #
# #Last write must be an empty string                                                                      #
# #                                                                                                        #
# sub chunked{                                                                                             #
#   #"x"x1024;                                                                                             #
#   #$scratch="";                                                                                          #
#                                                                                                          #
#   #matcher,rex, code, headers, data,cb,arg                                                               #
#   my $chunked_in=                                                                                        #
#   sub {                                                                                                  #
#     my $next=shift;                                                                                      #
#                                                                                                          #
#   };                                                                                                     #
#                                                                                                          #
#   my %out_ctx;                                                                                           #
#   my $chunked_out=                                                                                       #
#   sub {                                                                                                  #
#     my $next=shift;                                                                                      #
#     #my $bypass;                                                                                         #
#     #my $tmp;                                                                                            #
#     #my $scratch;                                                                                        #
#     my $index;                                                                                           #
#     my $i=1;                                                                                             #
#     my $ctx;                                                                                             #
#     sub {                                                                                                #
#       #say @_;                                                                                           #
#       if($_[CODE] and $_[CODE]!=304){                                                                    #
#         $ctx=undef;                                                                                      #
#         Log::OK::TRACE  and log_trace "Middeware: Chunked Outerware";                                    #
#         Log::OK::TRACE  and log_trace "Key count chunked: ". scalar keys %out_ctx;                       #
#         Log::OK::TRACE  and log_trace "Chunked: ". join " ", caller;                                     #
#         #\my $bypass=\$out_ctx{$_[1]}; #access the statefull info for this instance and requst           #
#         #my $exe;                                                                                        #
#         if($_[HEADER]){                                                                                  #
#           #$bypass=undef;#reset                                                                          #
#           \my @headers=$_[HEADER];                                                                       #
#                                                                                                          #
#           for my ($k,$v)(@headers){                                                                      #
#             $k eq HTTP_CONTENT_LENGTH and goto &$next                                                    #
#           }                                                                                              #
#                                                                                                          #
#           #(($_ eq HTTP_CONTENT_LENGTH)) and return &$next for(@headers[@key_indexes[0..@headers/2-1]]); #
#                                                                                                          #
#           #$exe=1;                                                                                       #
#           $ctx=1;                                                                                        #
#                                                                                                          #
#           Log::OK::TRACE and log_trace "Middelware: Chunked execute".($ctx//"");                         #
#                                                                                                          #
#           #we actually have  headers and Data. this is the first call                                    #
#           #Add to headers the chunked trasfer encoding                                                   #
#           #                                                                                              #
#                                                                                                          #
#           $index=undef;                                                                                  #
#           $i=1;                                                                                          #
#           for my ($k,$v)(@headers){                                                                      #
#             $i+=2;                                                                                       #
#             $index=$i and last if $k eq HTTP_TRANSFER_ENCODING;                                          #
#           }                                                                                              #
#                                                                                                          #
#           ########################################################                                       #
#           # my $index;                                           #                                       #
#           # $_ eq HTTP_TRANSFER_ENCODING and ($index=$_+1, last) #                                       #
#           #   for @headers[@key_indexes[0..@headers/2-1]];       #                                       #
#           ########################################################                                       #
#                                                                                                          #
#           unless($index){                                                                                #
#             push @headers, HTTP_TRANSFER_ENCODING, "chunked";                                            #
#                                                                                                          #
#           }                                                                                              #
#           else{                                                                                          #
#             $headers[$index].=",chunked";                                                                #
#                                                                                                          #
#           }                                                                                              #
#           #$ctx=$exe;                                                                                    #
#           $out_ctx{$_[REX]}=$ctx if $_[CB]; #save context if multishot                                   #
#           #no need to save is single shot                                                                #
#         }                                                                                                #
#                                                                                                          #
#         if($ctx//=$out_ctx{$_[REX]}){                                                                    #
#           #Process                                                                                       #
#           Log::OK::TRACE and log_trace join ", ",caller;                                                 #
#                                                                                                          #
#           Log::OK::TRACE and log_trace "Chunked: Testing for context";                                   #
#                                                                                                          #
#           Log::OK::TRACE and log_trace "DOING CHUNKS";                                                   #
#                                                                                                          #
#           # my $scratch=sprintf("%02X".CRLF, length $_[PAYLOAD]).$_[PAYLOAD].CRLF if $_[PAYLOAD];        #
#           #$tmp=$_[PAYLOAD];                                                                             #
#           #$scratch = $tmp?sprintf("%02X".CRLF, length $tmp).$tmp.CRLF : "";                             #
#           #$scratch = $_[PAYLOAD]?sprintf("%02X".CRLF, length $_[PAYLOAD]).$_[PAYLOAD].CRLF : "";        #
#           $_[PAYLOAD]= $_[PAYLOAD]?sprintf("%02X".CRLF, length $_[PAYLOAD]).$_[PAYLOAD].CRLF : "";       #
#                                                                                                          #
#           unless($_[CB]){                                                                                #
#             Log::OK::TRACE  and log_trace "Middleware chunked: no callback";                             #
#             #$scratch.="00".CRLF.CRLF;                                                                   #
#             $_[PAYLOAD].="00".CRLF.CRLF;                                                                 #
#                                                                                                          #
#             # Only need to delete if the is unset and no cb. (multicall)                                 #
#             # Otherwise it is a single call so not saved, thus no delete                                 #
#             delete $out_ctx{$_[REX]} unless $_[HEADER];                                                  #
#           }                                                                                              #
#                                                                                                          #
#           #$_[PAYLOAD]=$scratch;                                                                         #
#           goto &$next;                                                                                   #
#         }                                                                                                #
#         else {                                                                                           #
#           #nothing to process                                                                            #
#           Log::OK::TRACE  and log_trace "Middeware: Chunked ; no context. bybass";                       #
#           goto &$next                                                                                    #
#         }                                                                                                #
#       }                                                                                                  #
#       else{                                                                                              #
#         #Error condition. Reset stack                                                                    #
#         Log::OK::TRACE  and log_trace "Middeware: Chunked Passing on error condition";                   #
#         delete $out_ctx{$_[REX]};                                                                        #
#         goto &$next;                                                                                     #
#       }                                                                                                  #
#     };                                                                                                   #
#   };                                                                                                     #
#                                                                                                          #
#   [$chunked_in, $chunked_out]                                                                            #
# }                                                                                                        #
############################################################################################################
1;
