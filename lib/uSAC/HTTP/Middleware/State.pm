package uSAC::HTTP::Middleware::State;
use strict;
use warnings;

use Log::ger;
use Log::OK;

use uSAC::HTTP;
use feature qw<refaliasing say state current_sub>;
no feature "indirect";
no warnings "experimental";


use uSAC::HTTP::Code;# qw<:constants>;
use uSAC::HTTP::Header;# qw<:constants>;

use HTTP::State;
use HTTP::State::Cookie qw<:all>;


use Export::These "uhm_state";

# Middleware interfacing code for a HTTP state. Client side this is commonly called a cookie jar

sub uhm_state {
  [
  sub {
    # called when linking middleware

    my ($next, $index)=(shift, shift);
    my %options=@_;

    if($options{site}->mode){
      # True. client, want to process set-cookie headers into cookie jar
      Log::OK::TRACE and log_trace " HTTP State middleware configured for CLIENT";
    }
    else{
      Log::OK::TRACE and log_trace " HTTP State middleware configured for SERVER";
      # false server. 
      # Innerware simply parses the cookie header and stores it in state hash from innerware
      
      sub {
        Log::OK::TRACE and log_trace " Server side state management";
        return &$next unless $_[OUT_HEADER];

        my $state=$_[REX][STATE]//={};
        for my($k, $v)(decode_cookies $_[IN_HEADER]{HTTP_COOKIE()}){
          #say "K $k V $v";
          push $state->{$k}->@*, $v;
        }
        &$next;
      }
    }
  },

  sub {
    my ($next, $index)=(shift,shift);
    my %options=@_;
    if($options{site}->mode){
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
        return &$next unless $_[OUT_HEADER];


        #Convert any cookie structures to strings for direct rendering in output
        for my $set ($_[OUT_HEADER]{HTTP_SET_COOKIE()}//()){
          for my $cookie (@$set){
            $cookie=encode_set_cookie $cookie if ref $cookie;
          }
        }
        &$next;
      }
    }
  },

  undef
  ]
}


1;
