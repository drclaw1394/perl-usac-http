use strict;
use warnings;
use uSAC::HTTP ":constants";
use uSAC::HTTP::Route;

use Export::These "uhm_trace";

no warnings "experimental";

sub uhm_trace {
  [
    sub {
      my ($next, $index,%options)=@_;
      
      #TODO: test the options 
      sub {
        say "called with ", @_;

        # reconstruct the incomming request 
        my $body="";
        for($_[IN_HEADER]){
          $body=qq|$_->{":method"} $_->{":path"} http/1.1\n|;
          for my ($k, $v)($_->%*){
            next unless index $k, ":"; # Skip any headers with  ":"  prefix
            next if $k=HTTP_VIA;   #do not include via
            $body.="$k: $v\n";
          }
        }
        $body.="\n";
        # Add the via header
        $_[OUT_HEADER]{HTTP_VIA()}=$_[IN_HEADER]{HTTP_VIA()};

        # set the content typ
        $_[OUT_HEADER]{HTTP_CONTENT_TYPE()}="message/http";
        
        # return immediately
        $_[ROUTE][1][ROUTE_SERIALIZE]->&*;
        #return undef; 

      }
    },
    undef,
    undef
  ]
}
1;

=head1 NAME

U:T:M:Trace - HTTP/1.1 Trace Middeware

=head1 DESCRIPTION

Implements trace functionallity for HTTP/1.1. The incoming request (
request line and headers) are re serialised in to the repsonse body. 

This middleware expects to be the last in a chain so return immediately after.


