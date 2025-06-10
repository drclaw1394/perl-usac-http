use v5.36;
package uSAC::HTTP::Middleware::Authentication;
use feature "refaliasing";
no warnings "experimental";
use Import::These qw<uSAC::HTTP:: Code Rex Constants>;

use Export::These qw<uhs_authentication>;
use HTTP::State::Cookie qw<:all>;
use uSAC::HTTP::Middleware::Form;
use uSAC::HTTP::Code;# qw<:constants>;
use uSAC::HTTP::Header;# qw<:constants>;
use Log::OK;
use uSAC::Log;

use Cpanel::JSON::XS;
use Crypt::JWT;
use Data::Dumper;



# Returns a site hierrachy with routes  used for authentication
# User options
#
# login
# uri to the redirect to for html login page. a route needs to exist for this
# for both GET and POST methods
# If no login give the defualt site relative route (createded in this module )
# is used.
#
# logout
# is the logout route to complement the login. As per login
#
#
#
sub uhs_authentication {

  my %options=@_;

  # The routine to encode the cookie value and sign it if needed. Simply decodes json and forces authentication and non expiry
  
	my $state_encode=	$options{encode}//=sub {unpack("H*", &encode_json)};

  # The routine to decode and validate any signed values
  #/Users/drclaw/Documents/UNIX/perl/uSAC-HTTP-Middleware-Uploader 
	my $state_decode=	$options{decode}//=sub {[decode_json(pack("H*", $_[0])), 1, undef]};#//sub {$_[0]};


  # The name of a variable in a cookie which contains what we are after
	my $state_name=		$options{name}//"USAC_AUTHENTICATION";

  # The path, domain  expiry timesof the cookies
	my $state_path= 	$options{path}//"/";


  # The name of the field in the REX state with decoede client side state
	my $state_field=	$options{field}//$state_name;

  my $container_site=uSAC::HTTP::Site->new(id=>"auth_container");
  my $protected_site=uSAC::HTTP::Site->new(id=>"auth_protected", prefix=>"private/");
  my $login_site=uSAC::HTTP::Site->new(id=>"auth_login", prefix=>"auth/");

  my $use_builtin_routes= !$options{login};

  my $inner=sub {
    my $next=shift;
    my $index=shift;
    my %link_options=@_;
    my $b_prefix=$login_site->built_prefix;


    $options{login}//="${b_prefix}login";

    sub {
      Log::OK::TRACE and log_trace "AUTHENTICATION IINNER WARE++++";

      # Skip if we already have authentication. Could be a multi call (large body)
      #
      return &$next if $_[REX][AUTHENTICATION]->@*;


      # Assumes the state from the client has been stored via cookies, so check
      # the state in the rex      
      # If the it doesn't exist create
      #
      for my $v ((($_[REX][STATE]{$state_name})//[])->@*) {
        #
        # Process each of the values for the name   
        #

        # Decode if decoder provided, must return a decoded value, verified
        # flag, and expired flag
        #
        push $_[REX][AUTHENTICATION]->@*, $state_decode->($v);
      }

      # if valid and not expired, proceed to rest of middleware
      #
      for my $auth ($_[REX][AUTHENTICATION][0]){

        if($auth->[1] and !$auth->[2]){
          # data is valid and not expired . CONTINUE THROUGH MIDDLEWARE CHAIN
          Log::OK::TRACE and log_trace "---AUTHENTICATION OK CONTINUES=-----";
          Log::OK::TRACE and log_trace Dumper $auth;

          return &$next;
        }
        else {
          # Not authorized.
          #
          Log::OK::TRACE and log_trace "Not authorized+++ with method $_[REX][METHOD]";

          if($_[REX][METHOD] ne "GET" and $_[REX][METHOD] ne "HEAD"){
            # Straight up reject any non GET or HEAD requests
            Log::OK::TRACE and log_trace "DROPPING Non idemetic";
            $_[REX][uSAC::HTTP::Rex::closeme_]=1;
            $_[REX][uSAC::HTTP::Rex::session_]->drop();
          }
          else {
            # If its GET/HEAD we can redirect to login
            if($options{login}){
              Log::OK::TRACE and log_trace "Redirect to login";
              # We have a login page so internally redirect there!
              $_[REX][REDIRECT]=$options{login};#$_[REX][URI];

              # Also store the intended target as a cookie
              \my $set_cookies=\$_[OUT_HEADER]{HTTP_SET_COOKIE()};
              push $set_cookies->@*, encode_set_cookie cookie_struct  "target_uri", $_[REX][URI], path=> "/";

              #return &rex_redirect_internal;

              return &rex_redirect_found;
            }
            else {
              # authentication fail, drop connection
              Log::OK::TRACE and log_trace "JUST DROP THE CONNECTION";
              $_[REX][REDIRECT]=$_[REX][URI];
              $_[REX][STATUS]=HTTP_UNAUTHORIZED;
              $_[PAYLOAD]="NO access baby";

                # Use the error uri for the site
                return &rex_error;
            }
          }
        }
      }
    };
  };

  my $outer=sub {
    my $next=shift;
    sub {

      &$next;
    };
  };
  
  my $error=undef;


  $container_site->add_site($login_site);
  $container_site->add_site($protected_site);

  $protected_site->add_middleware( [$inner, $outer, $error]);


  # Add builtin routes if user has not provided routes for login and log out
  if($use_builtin_routes){
    # Routes to HTML interface for login and log out
    $login_site->add_route("GET", "login", 
      sub {
        # $_[PAYLOAD]="THIS IS LOGIN PAGE"; 1}
        $_[PAYLOAD]=qq{
        <html>
        <body>
        <form submit="login" method="POST">
        <input type="text" name="username"></input>
        <input type="password" name="password"></input>
        <input type="submit" name="login">Login</input>
        </form>
        </body>
        </html>
        };
      }
    );

    $login_site->add_route("GET", "logout", sub {
        $_[PAYLOAD]=qq{
        <html>
        <body>
          <form submit="logout" method="POST">
            <input type="submit" name="logout">Logout</input>
          </form>
        </body>
        </html>
        };
      }
    );

    # Built in submission for Login and log out forms
    #
    $login_site->add_route("POST", "login",   uhm_decode_form, sub {
        
        use uSAC::HTTP::Route;
        Log::OK::TRACE and log_trace " AUTH POST side state management route is: $_[ROUTE][0] site  $_[ROUTE][1][ROUTE_SITE] ";
        my $username=$_[PAYLOAD][0][1]{username};
        my $password=$_[PAYLOAD][0][1]{password};

        $_[PAYLOAD]= Dumper $_[PAYLOAD];
        $_[PAYLOAD].= "Username is $username, password is $password";
        $_[PAYLOAD].= Dumper $_[REX][STATE];


        # Decode the form

        # For now assume authenticated

        # Also store the intended target as a cookie
        \my $set_cookies=\$_[OUT_HEADER]{HTTP_SET_COOKIE()};
        push $set_cookies->@*, encode_set_cookie cookie_struct  $state_name, $state_encode->({username=>$username, data=>"abcd"}), path=> "/";
        push $set_cookies->@*, encode_set_cookie cookie_struct  "target_uri", "", "Max-Age"=>0, path=> "/";

        $_[REX][REDIRECT]=$_[REX][STATE]{target_uri}[0];
        Log::OK::TRACE and log_trace " AUTH POST side state management route before call is: $_[ROUTE][0] site  $_[ROUTE][1][ROUTE_SITE] ";
        &rex_redirect_found;

        0;

      }
    );

    $login_site->add_route("POST", "logout",  uhm_decode_form, sub {
        $_[PAYLOAD]= Dumper $_[PAYLOAD];

        # redirect to home page
        #
       
        # Expire authentications
        \my $set_cookies=\$_[OUT_HEADER]{HTTP_SET_COOKIE()};
        push $set_cookies->@*, encode_set_cookie cookie_struct  $state_name, $state_encode->({}), "Max-Age"=>0, path=> "/";
      }
    );

    # Static files for log in
    $protected_site->add_route("GET", "test", sub {
        $_[PAYLOAD]=Dumper $_[REX][AUTHENTICATION];
        1
      }
    );
  }


  $container_site;
}


1;
