package uSAC::HTTP::Middleware::TemplatePlex2;
use v5.36;
use feature "try";
use uSAC::HTTP;
use uSAC::HTTP::Constants;
use uSAC::Util;
use URI::Escape;


use Template::Plexsite;
use Template::Plexsite::URLTable;

use Export::These 'uhm_template_plex2';
# Template::Plex middleware driver 


sub uhm_template_plex2 {

  my %options=@_;

  my $url_table=$options{url_table};
  my $vars={
    route=>undef, 
    rex=>undef, 
    in_header=>undef, 
    out_header=>undef, 
    payload=>undef, 
    callback=>undef
  };
  

  my %reverse;
  # built reverse index
  for my ($k, $v)($url_table->table->%*){
    if($v->{template}){
      $reverse{"/".$v->{output}}=$k;
      say STDERR "/$v->{output} -> $k";
    }
  }

  my $prefix=$options{prefix};

  [
    sub {
    #my %options=@_;

    my ($next, $index)=@_;
      my $p;
      sub {
        # Check the url ends witha slash. If it doesnt. tell the client to redirect
        if($_[OUT_HEADER] and ($_[REX][STATUS]//HTTP_NOT_FOUND == HTTP_NOT_FOUND())){

          for($_[REX][PATH]){
            my @comp =split "/";

            # If the last component looks like a file.. go next
            if($comp[$#comp]=~/\./){
              $_[REX][STATUS]=HTTP_NOT_FOUND;
              return &$next;
            }
            
            # Redirect to url ending with slash if need be
            unless(m|/$|){
              $_[REX][REDIRECT]=$_[REX][PATH]."/";
              return &rex_redirect_see_other;
            }

            # Attempt to collapse path by extracting matching parameters
             
          }

          # Strip prefix
          #
          $p=uri_unescape $_[PAYLOAD]||$_[REX][PATH];
          $prefix//=ref($_[ROUTE][1][ROUTE_PATH]) ? "" : $_[ROUTE][1][ROUTE_PATH];

          $p=substr $p, length $prefix if (defined $prefix and index($p, $prefix)==0);

          #Update variables
          $vars->@{qw<route rex in_header out_header payload callback>}=@_;
          try {
            ##############################################
            # my $output= substr($_[PAYLOAD],0,1) ne "/" #
            #     ?"/".$_[PAYLOAD]                       #
            #     : $_[PAYLOAD];                         #
            #                                            #
            ##############################################
            my $output= substr($p,0,1) ne "/"
                ?"/".$p
                : $p;

            my @comps=split "/", $output; 

            # Shift off the root path
            shift @comps;

            # Translate to input namespace
            @comps=map {$_.".plt"} @comps;
            my $path=join "/", @comps;


            say STDERR " INPUT PATH FOR OUTPUT: $path ||||   $output";

            #$path=substr $path, 1;
            if($url_table->add_resource($path)){

              my %res=$url_table->build($path, $vars);
              $_[PAYLOAD]=$res{$path};

              $_[REX][STATUS]=HTTP_OK;
              $_[OUT_HEADER]{HTTP_CONTENT_LENGTH()}=length $_[PAYLOAD];
            }
            else {
              $_[REX][STATUS]=HTTP_NOT_FOUND;
              &$next;
            }
          }
          catch($e){
            say $e;
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
        &$next;
      }
    }
  ]
}
1;
