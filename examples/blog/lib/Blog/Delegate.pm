package Blog::Delegate;

use uSAC::HTTP;
use uSAC::HTTP::Middleware::Form;
use Template::Plexsite::URLTable;
#

use HTTP::State::Cookie ":all";
use Import::These qw<uSAC::HTTP::Middleware::
  Static Log Deflate Log
  Gzip Slurp ScriptWrap
  TemplatePlex2
  Redirect State
>;
no warnings "experimental";

#use Import::These qw<uSAC::HTTP::Middleware:: Log Static State Slurp>;

use HTTP::State::Cookie qw<:all>;
use uSAC::Util;
my $url_table=Template::Plexsite::URLTable->new(src=>path(\"../../src"), html_root=>path(\"../../static"), local=>undef);

  # Seed the table
  $url_table->add_resource("index.plt");

  $url_table->build();
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
    $site->add_middleware( _authenticate());

  }
}

# What to add as a route, in what order
# resolved names delegate methods automatically
sub auto_route_hook {
  sub {
    asay $STDERR, "Deletage auto route sub";
    my $site=shift; 
    $site->post("login")
    ->get("logout")

    #->post("posts/create")
    ->post("exact","posts")
    #->get("=~", "posts/$Decimal")

    #->get("=~", "posts/$Decimal/edit")
    #->add_route("PUT","=~","posts/$Decimal")
    #->add_route("DELETE","=~","posts/$Decimal")

    ->get("public")
    ->get("home")

    ->add_route('exact', 'static/hot.txt'
      => uhm_static_file(
        #headers=>{"transfer-encoding"=>"chunked"},
        \"../../static/hot.txt")
    );

    #->add_route('exact', 'static/hot.txt' => uhm_static_content "static/hot.txt");

    ###############################################################################
    # ->add_route(qr|getme/(($Comp)/)*($Comp)|n                                   #
    #   =>sub {                                                                   #
    #     $_[PAYLOAD]=join ", ", $_[IN_HEADER]{":captures"}->@*;                  #
    #     1;                                                                      #
    #   }                                                                         #
    # );                                                                          #
    #                                                                             #
    # $site->add_route("delay",                                                   #
    #   [                                                                         #
    #     sub {                                                                   #
    #       my $next=shift;                                                       #
    #       sub{                                                                  #
    #         use Time::HiRes "time";                                             #
    #         state $counter=0;                                                   #
    #         state $prev_counter=0;                                              #
    #         state $timer=uSAC::IO::timer 0, 2, sub {                            #
    #                                                                             #
    #           asay $STDERR, "Rate = @{[($counter-$prev_counter)/(2)]}";         #
    #           $prev_counter=$counter;                                           #
    #         };                                                                  #
    #                                                                             #
    #                                                                             #
    #         $counter++;                                                         #
    #         ##############################                                      #
    #         # my @msg=@_;                #                                      #
    #         # uSAC::IO::timer 2,0, sub { #                                      #
    #         #     $msg[PAYLOAD]=time;    #                                      #
    #         #     $next->(@msg);         #                                      #
    #         # };                         #                                      #
    #         ##############################                                      #
    #                                                                             #
    #         $_[PAYLOAD]=time;                                                   #
    #                                                                             #
    #         if($_[REX][STATE]->%*){                                             #
    #           adump $STDERR, $_[REX][STATE];                                    #
    #           \my @sc=$_[OUT_HEADER]{HTTP_SET_COOKIE()}//=[];                   #
    #           push @sc, cookie_struct "sid1"=>"asdf";                           #
    #           push @sc, cookie_struct "sid2", "value1";                         #
    #         }                                                                   #
    #                                                                             #
    #         &$next;                                                             #
    #       }                                                                     #
    #     }                                                                       #
    #   ]                                                                         #
    # );                                                                          #
    # $site->add_route("redirect"                                                 #
    #   =>sub {                                                                   #
    #     $_[REX][STATUS]=301;                                                    #
    #     $_[OUT_HEADER]{HTTP_LOCATION()}="http://localhost:8084/static/hot.txt"; #
    #   }                                                                         #
    # )                                                                           #
    ###############################################################################


    $site->add_route([qw<GET HEAD>],''
      => uhm_gzip()
      => uhm_template_plex2(url_table=>$url_table)
      => uhm_static_root(
        #index=>["index.html"],
        #list_dir=>1,
        roots=> [\"../../static", \"../../admin/static"],
        #template=>qr/\/$/
      )

    );

    $site->add_route("");
  $site->add_route("more_testing"=>sub {
      $_[PAYLOAD]="asdf";
      1;
    });

  #$site->add_route($Any_Method, "");


  }
}


# Implicit routing
#

sub _POST__begin__login_ {
  (
    uhm_slurp(),    # Ensure the entire contents of the request are received #

    sub {
      adump $STDERR, "post loin";
      my $details=decode_urlencoded_form $_[PAYLOAD][0][1];
      # Check the CSRF token is valid
      adump $STDERR, $details;


      for($details->{authentication_token}){
        my $data=verify_protection_token($_);
        #my $jwt=decode_jwt(token=>$_, key=>$secret);
        adump $STDERR, $data;

        if(defined $data){
          # Here we validate the content of the form
          $_[PAYLOAD]=$details;
          &_handle_login_cb;
        }
        else {
          &rex_error_forbidden;
        }
      }
      1;
    }
  )
}

sub _POST__exact__posts_ {
  # handle form submission
  (
    uhm_decode_form(),
    sub {
      adump $STDERR, $_[PAYLOAD];
      $_[REX][REDIRECT]="/posts/";
      &rex_redirect_found; 

      1;
    }
  )
}


sub _handle_login_cb {
  adump $STDERR, "in handle long in cb";
  my $details=$_[PAYLOAD];
  my $set=$_[OUT_HEADER]{HTTP_SET_COOKIE()}//=[];
  for($details->{username}){
    push @$set, 
    cookie_struct 
    "SESSION_ID"=>ref?$_->[0]:$_, 
    #"Max-Age"=>100, 
    path=> '/';
  }
  $_[REX][REDIRECT]=$details->{target}|| "/home";
  return &rex_redirect_see_other;
}


sub _GET__begin__logout_ {
  (
    sub {
      my $set=$_[OUT_HEADER]{HTTP_SET_COOKIE()}//=[];
      push @$set, cookie_struct SESSION_ID=>"", "max-age"=>1, path=>"/";

      $_[PAYLOAD]="";
      $_[REX][REDIRECT]="/login/";
      &rex_redirect_see_other;
      1;
    }
  )
}




sub _GET__begin__public_ {
  (uhm_static_root(read_size=>4096, do_dir=>1, \undef));
}


sub _GET__begin__home_ {
    sub {
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
}

sub _GET__begin___ {
  sub {
   $_[REX][STATUS]=HTTP_OK;
   $_[PAYLOAD]="lkjalsdkjalkjasdf";
   1;
  }
}


sub _authenticate {
    [
      sub {
        my ($next, $index)=(shift, shift);
        sub{
          # session id is stored in cookie. check if session is valid
          for my $state ($_[REX][STATE]){
            $state//={decode_cookies $_[IN_HEADER]{HTTP_COOKIE()}};

            if($state->{"SESSION_ID"}){
              # Validate the session and continue
              &$next;
            }
            else {
              # No session_ID. Force a showing of a login page, redirect to login
              unless($_[REX][PATH] =~ m"^/login"){
                $_[REX][REDIRECT]="/login";#$_[REX][PATH];
                $_[PAYLOAD]="/login";#?target=$in_header{':path'}";
                &rex_redirect_see_other ;
                return undef;
              }
              else {
                # This is the login page
                &$next;
              }

            }
            }
          }
        }
    ]
}




sub test {
  sub {
  (
    sub {
      \my %kv=$_[IN_HEADER]{":state"};
      if($kv{name}){
        asay $STDERR, "Existing cookie from client";
        # Validate 
        asay $STDERR, "ok" if $kv{name} =~ /value/;
      }
      else {
        #say "No cookie... setting";
        my $c=cookie_struct name=>"value";#, COOKIE_PATH()=>"/static";

        local $_=$_[OUT_HEADER]{HTTP_SET_COOKIE()}= [ encode_set_cookie($c)];
        $c=cookie_struct name2=>"new value";
        push @$_, encode_set_cookie($c);
      }
      1;
    }
  )
  }
}


# return the name of the package... 
__PACKAGE__;

