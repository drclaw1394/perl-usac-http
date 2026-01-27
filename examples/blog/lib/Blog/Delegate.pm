package Blog::Delegate;

use uSAC::HTTP;
use uSAC::HTTP::Middleware::Form;
use uSAC::HTTP::Middleware::Authentication;

use Template::Plexsite::URLTable;


use Import::These qw<uSAC::HTTP::Middleware::
  Static Log Deflate Log
  Gzip ScriptWrap
  TemplatePlex2
  Redirect State
>;

no warnings "experimental";


use uSAC::Util;

my @middleware=(
  uhm_http_authentication(
            schemes=>[
              {
                scheme=>"cookie",
                realm=>"asdf",
                charset=>"utf8",
                cookie_name=>"SESSION_ID",
                redirect=>"/login",
                auth_cb=> sub {
                  adump $STDERR, "-home auth ",@_;

                  if(ref $_[0]){
                    # Encode (json, jwt, etc) and return contents for a set cookie header

                    # look up  credentials/session/etc

                    my $is_check;
                    # update internal session details if required

                    #my $data=
                    $_[1]->("serialized auth");

                  }
                  else {
                    # Decode a string into 
                    asay $STDERR, "GOT AUTH CALLBACK cookie";
                    $_[1]->({username=>"test"});

                  }
                }
              },
              {
                scheme=>"basic",
                realm=>"asdf",
                charset=>"utf8",
                auth_cb=> sub {
                  if(ref $_[0]){
                    # Encode
                  }
                  else {
                    # Decode
                    asay $STDERR, "GOT AUTH CALLBACK basic";
                    $_[1]->({username=>"test"});
                  }
                }
              }
            ]
            #################################################
            # {                                             #
            #   scheme=>"bearer",                           #
            #   realm=>"my relm",                           #
            #   auth_cb=>sub {                              #
            #     asay $STDERR, "GOT AUTH CALLBACK bearer"; #
            #     ({username=>"test"});                     #
            #                                               #
            #   }                                           #
            # }                                             #
            #################################################
          )
);

# Factory method. Returns the sub
# The sub modifies the site, does not return anything
#
sub app {

  # Return a hook
  sub {
    my $site=shift;

    # Set the delegate to resolve implicit routes.. 
    # must be manually set if a code ref is returned
    $site->add_delegate(__PACKAGE__);


    my $url_table=Template::Plexsite::URLTable->new(
      src=>path(\"../../src"), 
      html_root=>path(\"../../static"), 
      local=>undef
    );


    # What to add as a route, in what order
    # resolved names delegate methods automatically
    asay $STDERR, "Deletage auto route sub";
    $site->post("login", uhm_login auth_cb => sub {
        if(ref $_[0]){
          #  Test the details against db, ....

          #  Call the callback with the data to encode in the cookie
          #
          $_[1]->("auth data") ;
        }
        else {
          # Decode and authenticate and return structure
        }
      }
    );

    $site->get(begin=>login=>
      uhm_template_plex2( url_table=>$url_table, prefix=>"")
    );


    my $protected=uSAC::HTTP::Site->new(delegate=>__PACKAGE__);
    $protected->add_middleware(@middleware);

    $protected->post("logout", uhm_logout);



    $protected->get("posts/create");
    $protected->post("exact","posts");





    #->get("=~", "posts/$Decimal/edit")
    #->add_route("PUT","=~","posts/$Decimal")
    #->add_route("DELETE","=~","posts/$Decimal")


    $protected->get("=~",     "posts/($Decimal)", "posts_id");
    $protected->get("public", "public");
    $protected->get("home",   "home");

    $protected;
    $protected->add_route('exact', 'static/hot.txt'
      => uhm_static_file(
        #headers=>{"transfer-encoding"=>"chunked"},
        \"../../static/hot.txt"
      )
    );




    $protected->add_route([qw<GET HEAD>],''
      => uhm_gzip()
      => uhm_template_plex2(url_table=>$url_table)
      => uhm_static_root(
        #index=>["index.html"],
        #list_dir=>1,
        roots=> [\"../../static", \"../../admin/static"],
        #template=>qr/\/$/
      )


    );

    $site->add_site($protected);

    $site->add_route("");
  }
}

# Implicit routing
#

sub _POST__begin__login_ {
  uhm_login auth_cb => sub {
    if(ref $_[0]){
      #  Test the details against db, ....


      #  Call the callback with the data to encode in the cookie
      #
      $_[1]->("auth data") ;
    }
    else {
      # Decode and authenticate and return structure
    }
  }
}

sub _POST__exact__posts_ {
  # handle form submission
  (
    uhm_decode_form(),

    sub {
      adump $STDERR, $_[PAYLOAD];

      my $token=$_[PAYLOAD][0][PART_CONTENT]{protection_token};
      asay $STDERR, $token;

      $_[REX][REDIRECT]="/posts/";
      &rex_redirect_found; 

      1;
    }
  )
}

sub _GET__begin__posts__create_ {
  
}

sub _GET__regexp__posts_id_ {

  (
    sub {
      adump $STDERR,"Captures", $_[REX][CAPTURES];
      1;
    }
  )
}


sub _POST__begin__logout_ {
  (
    uhm_logout
  )
}


sub _GET__begin__public_ {
  (uhm_static_root(read_size=>4096, do_dir=>1, \undef));
}


sub _GET__begin__home_ {
  (
    sub {
      asay $STDERR, "CALLED HOME------";
      $_[OUT_HEADER]{HTTP_CONTENT_TYPE()}="text/html";
      $_[PAYLOAD]=qq|
      <html>
      <head>
      <title> Home </title>
      </head>
      <body>
      HELLO there
      </body>
      </html>
      |;
    }
  )
}

sub _GET__begin___ {
  sub {
    $_[REX][STATUS]=HTTP_OK;
    $_[PAYLOAD]="lkjalsdkjalkjasdf";
    1;
  }
}

#=========
# Hooks.
#  Hooks return a sub to actually be called
#

sub process_cli_options_hook {
  sub {
    asay $STDERR, "CLI options hook in delegate ". __PACKAGE__;#, $_[0]->@*;
  }
}

# return a list of middleware to add before calling each delegate method
sub middleware_hook {
  sub {
    my $site=shift;
    #$site->add_middleware( uhm_state);
    #$site->add_middleware( _authenticate());

  }
}

sub auto_route_hook {
  sub {
  }
}

# return the name of the package...

__PACKAGE__;

\&app;
