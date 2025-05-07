package uSAC::HTTP::Middleware::Trace;
use strict;
use warnings;

use uSAC::HTTP::Constants;
use uSAC::HTTP::Route;
use uSAC::HTTP::Header;

use Export::These "uhm_trace";

no warnings "experimental";

sub uhm_trace {
  [
    sub {
      my ($next, $index,%options)=@_;
      
      #TODO: test the options 
      sub {

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
        
        $_[REX][uSAC::HTTP::Rex::serializer_]->&*;
        # return immediately
        #$_[ROUTE][1][ROUTE_SERIALIZE]->&*;
        #my $s=$_[REX][uSAC::HTTP::Rex::session_]->get_serializer();
        #&$s; 
        #return undef; 

      }
    },
    undef,
    undef
  ]
}
1;
