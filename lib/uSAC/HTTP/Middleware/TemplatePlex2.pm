package uSAC::HTTP::Middleware::TemplatePlex2;
use v5.36;
use feature "try";
use uSAC::HTTP;
use uSAC::HTTP::Constants;
use uSAC::Util;


use Template::Plex;

use Export::These 'uhm_template_plex2';
# Template::Plex middleware driver 


sub uhm_template_plex2 {

  my %options=@_;

  my $vars={
    route=>undef, 
    rex=>undef, 
    in_header=>undef, 
    out_header=>undef, 
    payload=>undef, 
    callback=>undef
  };
  
  [
    sub {
    #my %options=@_;

    my ($next, $index)=@_;
      sub {
        if($_[OUT_HEADER] and  !defined $_[REX][STATUS]){
          #Update variables
          $vars->@{qw<route rex in_header out_header payload callback>}=@_;
          try {
            $_[PAYLOAD]=Template::Plex->immediate(undef, $_[PAYLOAD], $vars);
            $_[REX][STATUS]=HTTP_OK;
            $_[OUT_HEADER]{HTTP_CONTENT_LENGTH()}=length $_[PAYLOAD];
          }
          catch($e){
            $_[PAYLOAD]= $e;
            $_[REX][STATUS]=HTTP_INTERNAL_SERVER_ERROR;
          }
        }
        &$next;
      }
    },

    undef,

    sub {
      my ($next, $index)=@_;
      sub {
        #Force delete context
        #delete $ctx{$_[REX]};
        &$next;
      }
    }
  ]
}
1;
