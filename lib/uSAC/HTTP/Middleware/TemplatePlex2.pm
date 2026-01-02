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
  Error::Show::throw "No html_root specified" unless $options{html_root};
  Error::Show::throw "No wrc specified" unless $options{src};
  my $url_table=Template::Plexsite::URLTable->new(src=>$root, html_root=>$options{html_root}, locale=>undef);
  [
    sub {
    #my %options=@_;

    my ($next, $index)=@_;
      sub {
        # Check the url ends witha slash. If it doesnt. tell the client to redirect
        #asay $STDERR, "ROOT IS $root";
  #asay $STDERR, "IN template plexsite 2";
        #asay $STDERR, "STATUS IN IS $_[REX][STATUS]";
        if($_[OUT_HEADER] and $_[REX][STATUS] != HTTP_OK()){

          # Redirect to url ending with slash if need be
          for($_[REX][PATH]){
            unless(m|/$|){
              $_[REX][REDIRECT]=$_[REX][PATH]."/";
              return &rex_redirect_see_other;
            }
          }

          #Update variables
          $vars->@{qw<route rex in_header out_header payload callback>}=@_;
          try {
            #my $path=substr $_[REX][PATH],0 ,-1;
            my $path=substr $_[PAYLOAD],0 ,-1;
            $path.=".plt";

            $path=substr $path, 1;
            my @input=$url_table->add_resource($path);

            my $info=$url_table->resource_info($path);

            if($info){
              my %res=$url_table->build($path);
              $_[PAYLOAD]=$res{$path};

              $_[REX][STATUS]=HTTP_OK;
              $_[OUT_HEADER]{HTTP_CONTENT_LENGTH()}=length $_[PAYLOAD];
            }
            else {
              $_[REX][STATUS]=HTTP_NOT_FOUND;
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
        #Force delete context
        #delete $ctx{$_[REX]};
        &$next;
      }
    }
  ]
}
1;
