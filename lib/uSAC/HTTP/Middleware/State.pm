package uSAC::HTTP::Middleware::State;
use strict;
use warnings;
use feature qw<refaliasing say state current_sub>;
no warnings "experimental";
no feature "indirect";

use Log::ger;
use Log::OK;

use uSAC::HTTP;


use uSAC::HTTP::Code qw<:constants>;
use uSAC::HTTP::Header qw<:constants>;
use HTTP::State qw<:all>;
use HTTP::State::Cookie qw<:all>;

use Exporter 'import';

our @EXPORT_OK=("uhm_state");
our @EXPORT=@EXPORT_OK;

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
      # Innerware simply parses the cookie header and stores it in state hash
      
      sub {
        Log::OK::TRACE and log_trace " Server side state management";
        if($_[OUT_HEADER] and $_[IN_HEADER]{HTTP_COOKIE()}){
          # If there is a cookie header and it hasn't been parsed, parse it
          my $state=$_[IN_HEADER]{":state"}={};

          for my($k,$v)(decode_cookies $_[IN_HEADER]{HTTP_COOKIE()}){
            if(!exists $state->{$k}){
              # First value 
              $state->{$k}=$v;
            }
            elsif(ref $state->{$k}){
              # Existing ref Multiple values here
              push $state->{$k}->@*, $v; 
            }
            else{
              # Existing value, but wasn't a ref, wrap it
              $state->{$k}=[$state->{$k}, $v];
            }
          }
        }
        &$next;
      }
    }
  },
  undef,
  undef
  ]
}


1;
