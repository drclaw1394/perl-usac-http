use v5.36;
package uSAC::HTTP::Middleware::State;

use uSAC::Log;
use Log::OK;

use uSAC::HTTP;
use feature qw<refaliasing state current_sub>;
no feature "indirect";
no warnings "experimental";


use uSAC::HTTP::Code;# qw<:constants>;
use uSAC::HTTP::Header;# qw<:constants>;

use uSAC::HTTP::Constants;
use HTTP::State;
use HTTP::State::Cookie qw<:all>;

use uSAC::HTTP::Route;

use Export::These "uhm_state";

# Middleware interfacing code for a HTTP state. Client side this is commonly called a cookie jar

sub uhm_state {
  [
  sub {
    # called when linking middleware

    my ($next, $index)=(shift, shift);
    my %options=@_;

    if($options{site}->mode == 2){
      # True. client, want to process set-cookie headers into cookie jar
      Log::OK::TRACE and log_trace " HTTP State middleware configured for CLIENT";
    }
    else{
      Log::OK::TRACE and log_trace " HTTP State middleware configured for SERVER";
      # false server. 
      # Innerware simply parses the cookie header and stores it in state hash from innerware
      
      sub {
        # If we have already setup state, skip
        return &$next if $_[REX][STATE];
        Log::OK::TRACE and log_trace " Server side state management";
        Log::OK::TRACE and log_trace " Server side state management route is: $_[ROUTE][0] site  $_[ROUTE][1][ROUTE_SITE] ";
        #Log::OK::TRACE and log_trace "State decoded  for rex $_[REX] before: ".Dumper $_[REX];

        my $state=$_[REX][STATE]//={};
        for my($k, $v)(decode_cookies $_[IN_HEADER]{HTTP_COOKIE()}){
          push $state->{$k}->@*, $v;
        }
        #Log::OK::TRACE and log_trace "State decoded for rex $_[REX]: ".Dumper $_[REX];
        &$next;
      }
    }
  },

  sub {
    my ($next, $index)=(shift,shift);
    my %options=@_;
    if($options{site}->mode == 2){
      # true is client mode.  Th
      # The REX STATE variable is used as a place holder to store the cookies retrieved from the cookie jar
      #$_[OUT_HEADER]{HTTP_COOKIE()}=encode_cookie
    }
    else{
      # 
      # Otherwise server mode IN server mode we want to take the cookies stored
      # in :state (output header) and serialize them into multiple head lines
      #
      sub {
        # Out header is undef when header has been written. So only encode headeres and state when there is an outheader present
        #
        return &$next unless $_[OUT_HEADER];


        #Convert any cookie structures to strings for direct rendering in output
        for my $set ($_[OUT_HEADER]{HTTP_SET_COOKIE()}//()){
          for my $cookie (@$set){
            $cookie=encode_set_cookie $cookie if ref $cookie;
          }
        }

        # The state in rex is what has come back from the client, not what is to encoded
        &$next;
      }
    }
  },

  undef
  ]
}


1;
