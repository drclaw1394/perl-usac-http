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


1;
