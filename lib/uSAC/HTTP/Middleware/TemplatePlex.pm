package uSAC::HTTP::Middleware::Trace;
use strict;
use warnings;
use uSAC::HTTP;
use uSAC::HTTP::Constants;
use uSAC::Util;


use Export::These 'uhm_template_plex';
# Template::Plex middleware driver 


sub uhm_template_plex {
  # Even though Template::Plex is a dependency elsewhere
  # serve as example for other drivers
  require Template::Plex;
  my %ctx;
  my $path=uSAC::Util::path(pop,[caller]);

  my %options=@_;

  my $vars={
    route=>undef, 
    rex=>undef, 
    in_header=>undef, 
    out_header=>undef, 
    payload=>undef, 
    callback=>undef
  };
  
  my $template=Template::Plex->load($path, $vars);
  [
    sub {
    #my %options=@_;

    my ($next,$index)=@_;
      sub {
        my $ctx;
        if($_[OUT_HEADER]){
          # First call

          #Store the context if callback is provided
          #
          $ctx=$vars;
          $ctx{$_[REX]}=$ctx if $_[CB];
        }
        
        # Process 
        $ctx//=$ctx{$_[REX]};
        

        #Update variables
        $ctx->@{qw<route rex in_header out_header payload callback>}=@_;

        $_[PAYLOAD]=$template->render;
        #Delete context if we are finished
        delete $ctx{$_[REX]} unless $_[CB];
        &$next;
      }
    },
    undef,
    sub {
      my ($next,$index)=@_;
      sub {
        #Force delete context
        delete $ctx{$_[REX]};
        &$next;
      }
    }
  ]
}
1;
