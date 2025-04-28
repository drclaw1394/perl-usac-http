package uSAC::HTTP::Middleware::TemplatePlex2;
use v5.36;
use feature "try";
use uSAC::HTTP;
use uSAC::HTTP::Constants;
use uSAC::Util;


use Template::Plexsite;
use Template::Plexsite::URLTable;

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
  
  my $root=uSAC::Util::path $options{src}, [caller];
  [
    sub {
    #my %options=@_;

    my ($next, $index)=@_;
      sub {
        if($_[OUT_HEADER] and  !defined $_[REX][STATUS]){
          #Update variables
          $vars->@{qw<route rex in_header out_header payload callback>}=@_;
          try {
            my $url_table=Template::Plexsite::URLTable->new(src=>$root);
            my $path=$_[REX][PATH].".plt";
            $path=substr $path, 1;
            my $input=$url_table->add_resource($path);
            my $info=$url_table->resource_info($path);

            #use Data::Dumper;
            #$url_table->add_resource($input);
            #$_[PAYLOAD]=$info->{template}{template}->render;
            #
            if($info){
              $_[PAYLOAD]=$info->{template}{template}->render;

              $_[REX][STATUS]=HTTP_OK;
              $_[OUT_HEADER]{HTTP_CONTENT_LENGTH()}=length $_[PAYLOAD];
            }
            else {
              $_[REX][STATUS]=HTTP_NOT_FOUND;
            }
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
