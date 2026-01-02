package Blog::Delegate;

use uSAC::HTTP;
use uSAC::HTTP::Middleware::Form;
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



sub process_cli_options_hook {
  sub {
    asay $STDERR, "CLI options hook in delegate ". __PACKAGE__;#, $_[0]->@*;
  }
}

sub auto_route_hook {
  sub {
    asay $STDERR, "Deletage auto route sub";
    my $site=shift; 
    $site->add_route(POST=>"login")
    ->add_route("login")
    ->add_route("logout")
    ->add_route("public")
    ->add_route("home")

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


    $site->add_route('static'
      => uhm_static_root(
        #index=>["index.html"],
        #list_dir=>1,
        roots=> [\"../../static", \"../../admin/static"],
        template=>qr/\/$/
      )
      => uhm_template_plex2 src=>path(\"../../src"), html_root=>path(\"../../static")

    );
  $site->add_route("more_testing"=>sub {
      $_[PAYLOAD]="asdf";
      1;
    });

  #$site->add_route($Any_Method, "");


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


# return a list of middleware to add before calling each delegate method
sub middleware_hook {
  sub {
    my $site=shift;
    #$site->add_middleware( uhm_state);
    $site->add_middleware( _authenticate);

  }
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

# Implicit routing
#

sub _login_{
  (
                    
    uhm_slurp(),    # Ensure the entire contents of the request are received
    sub {
      for($_[REX][METHOD]){
        /GET/ and return &_GET_login; 
        /POST/ and return &_POST_login;
        return &rex_error_not_found;
        }
      }
  )
}

sub _GET_login {
  $_[OUT_HEADER]{HTTP_CONTENT_TYPE()}="text/html";

  my $jwt=generate_protection_token("data");
  
  # Render the page for login?
  state $form=Template::Plex->load([q|
      <html>
        <body>
          <form action="/login" method="POST">
            <label for="username">Username</label>
            <input name="username">

            <label for="password">Password</label>
            <input name="password" type="password">

            <input name="target" hidden value="/home">
            <input name="authentication_token" hidden value="$fields{token}">
            <input type="submit">
          </form>
        </body>
      </html>
      |]);

  $_[PAYLOAD]=$form->render({token=>$jwt});
  1;
}

sub _POST_login {
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


sub _logout_ {
  (
    sub {
      my $set=$_[OUT_HEADER]{HTTP_SET_COOKIE()}//=[];
      push @$set, cookie_struct SESSION_ID=>"", "max-age"=>1, path=>"/";

      $_[PAYLOAD]="";
      $_[REX][REDIRECT]="/login";
      &rex_redirect_see_other;
      1;
    }
  )
}

sub _public_ {
  (uhm_static_root(read_size=>4096, do_dir=>1, \undef));
}


sub _home_ {
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

sub __ {
  sub {
   $_[REX][STATUS]=HTTP_OK;
   $_[PAYLOAD]="lkjalsdkjalkjasdf";
   1;
  }
}

# return the name of the package... 
__PACKAGE__;

