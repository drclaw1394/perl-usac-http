use v5.36;
package uSAC::HTTP::Middleware::Authentication;
use feature "refaliasing";
no warnings "experimental";
use uSAC::IO;
use Import::These qw<uSAC::HTTP:: Code Rex Constants>;

use Export::These qw<uhm_http_authentication>;
use HTTP::State::Cookie qw<:all>;
use uSAC::HTTP::Middleware::Form;
use uSAC::HTTP::Code;# qw<:constants>;
use uSAC::HTTP::Header;# qw<:constants>;
use Log::OK;
use uSAC::Log;

use Cpanel::JSON::XS;
use Crypt::JWT;


=pod

=head1 NAME

HTTP AUTHENTICATION

=head2 DESCRIPTION

Implements HTTP Authentication schemes (Basic, Digest and Bearer). Also
supports cookie authentication. Multiple schemesare supported at once.

Both http and cookies schemes (multiple of both) can be used at once.  A client
can respond to either 0 or more of these by either sending the Authorize header
or a cookie with the credentials.

Cookie and Bearer schemes are application  specific in what information is
encoded decoded. This could be a simple session ID  or a JWT for example. 

=head2 AUTHENTICATION FAILURE

If http schemes only are configured,  all failures generate the
WWW-Authenticate headers rendered for all configured http schemes.

If ONLY http schemds are configured, a 401 response is returned.

If ONLY cookie schemes are confitured, the location is set and a 303 see other is the response.

If both cookie and http schemes are configured, www-authenticate headers are
set, but the return status is base on the first scheme in the configuration
list. If it is acookie, the status will be a redirect. Otherwise a 401.

This allows for the same url end point to utilised either cookie or http
authentication. (ie one for web browsers, and the other for api clients)


At least one authentication must be present to pass.

All authentication present must pass.

=head2 SCHEME SPECIFICATION

A scheme is a hash ref. Require keys for http schems are the 'scheme', 'realm'
For cookie schemes, 'scheme', 'name' (of cookie)  and 'redirect' keys are required.

All  require 'auth_cb' and scheme.

=head3 auth_cb

The auth callback is passed the either the parsed kv pairs or the raw token value, as the first arugument. THe second argument is the finalising callback function to pass the authorised information and can be called asynchronously.

=cut


=head2 uhm_http_authentication

Middleware to handling the http authorizing and cookie based authentication.
Takes 1 or more  schemes to implement restricted access to a resource

=cut 

sub uhm_http_authentication {
  
  my %options=@_;
  my $methods=$options{schemes}//[]; # an array of hashes
  
  my @http_methods;
  my @cookie_methods;

  # Iterate through each of the methods and make sure handlers are set
  for(@$methods){
    $_->{scheme}=lc $_->{scheme};
    if($_->{scheme} eq "basic"){
      $_->{parser}//=basic_parser();
      #$_->{serializer}//=\&basic_serializer;
      push @http_methods, $_;
    }
    elsif($_->{scheme} eq "digest"){
      $_->{parser}//=digest_parser();
      #$_->{serializer}//=\&digest_serializer;
      push @http_methods, $_;
    }
    elsif($_->{scheme} eq "bearer"){
      $_->{parser}//=bearer_parser();
      #$_->{serializer}//=\&bearer_serializer;
      push @http_methods, $_;
    }
    elsif($_->{scheme} eq "cookie"){
      $_->{parser}//=cookie_parser();
      #$_->{serializer}//=\&cookie_serializer;
      push @cookie_methods, $_;
    }
    else {
      die "No parser specified for $_->{scheme}";
    }
    
  }

  # Determin the default error/redirect for mixeed mode routes
  my $redirect_location;

  my $web_error_mode;
  if(($methods->[0]//{})->{scheme} eq "cookie"){
    $web_error_mode="redirect";
    $redirect_location=$methods->[0]{redirect};
  }

  [sub {
      my ($next, $index)=@_;
      sub {

          asay $STDERR, "WOrking on auth oi";
        if($_[OUT_HEADER]){

          asay_now $STDERR, "WOrking on auth";
          my @parsed_http;
          my @parsed_cookie;
          my $counter;


          if(@http_methods){
            for($_[IN_HEADER]{HTTP_AUTHORIZATION()}){
              if($_){
                my ($scheme, $credentials)=split " ", $_, 2;
                $scheme=lc $scheme;

                for(@http_methods){
                  next unless $_->{scheme} eq $scheme;


                  # Call scheme handler
                  my $parser=$_->{parser};
                  my $params=$parser->($_, $credentials);


                  $counter++;
                  push @parsed_http, $_, $params; 

                  last; # only ever process one
                }
              }
            }
          }

          if(@cookie_methods){
            adump $STDERR, "Cookie method ";
            for my $state($_[REX][STATE]//={decode_cookies $_[IN_HEADER]{HTTP_COOKIE()}}){
              adump $STDERR, "state ", $state;
              for(@cookie_methods){
                my $credentials=$state->{$_->{name}};
                if($credentials){
                  my $parser=$_->{parser};
                  my $params=$parser->($_, $credentials);
                  push @parsed_cookie, $_, $params; 
                }
                else {
                  #none
                }
              }
            }
          }
          

          $counter+=@parsed_cookie/2;
          my $total=$counter;

          if($counter == 0){
            # No authentication even attempted..header or cookie... send the
            # required reqponse
            #
            my @header;
            for(@http_methods){
              push @header, $_->{parser}->($_);
            }
            $_[OUT_HEADER]{HTTP_WWW_AUTHENTICATE()}=join ", ", @header;
              adump $STDERR, @header;



            if($web_error_mode eq "redirect"){
              # uSes the first cookie spec as location
              $_[REX][REDIRECT]=$redirect_location;
              return &rex_redirect_see_other;
            }
            else {
              return &rex_error_unauthorized;
            }
          }

          else {
            my @args=@_;
            my @authenticated;
            my $cb= sub {
              adump $STDERR, "Doing callback with auth results ", @_;
              # Call back with authentication information
              #push $_[REX][AUTHENTICATION]->@*,
              push @authenticated, @_;
              $counter--;
              if($counter==0){
                # if both headers sent and any fail, error unauthorised
                # If a auth header (only) was sent and fails, error unauthorised
                # If cookie (only) was sent without no auth headers, and auth fails, redirect and code?
                # If no auth header or cookie , redirect to login
                
                if(@authenticated != $total){
                  # at  least one authentication failure... UN AUTHORISED
                  if(@parsed_http){
                    #http or both http and cookie headers sent. fail with unauthorized
                    my @header;
                    for(@http_methods){
                      push @header, $_->{parser}->($_);
                    }
                    $_[OUT_HEADER]{HTTP_WWW_AUTHENTICATE()}=join ", ", @header;
                    &rex_error_unauthorized;
                  }
                  elsif(@parsed_cookie){
                    # only cookie header used. fail with redirect
                    $_[REX][REDIRECT]=$redirect_location;
                    &rex_redirect_see_other;
                  }
                }
                else {
                  # all authenticated! continue!
                  push $_[REX][AUTHENTICATION]->@*, @authenticated;
                  $next->(@args);
                }
              }
              else {
                # Work still outstanding
                # Need to setup up a time out to destroy this sub
              }
            };

            # Call all the authentication methods
            # and wait for callbacks
            for my($s, $v) (@parsed_http, @parsed_cookie){
              $s->{auth_cb}($v, $cb);
            }
          }
        }
        else {
          &$next;
        }
      }
  }
  ]
}

sub basic_parser {
  sub {
    if($_[1]){
      my $credentials=eval {MIME::Base64::decode_base64($_[1])};
      my ($user, $pass)=split ":", $credentials, 2;
      my %params=(
        username=>$user,
        password=>$pass.
        realm=>$_[0]{realm},
        label=>$_[0]{label},
        scheme=>$_[0]{scheme}
      );

      return  \%params;
    }
    else {
      my $h="Basic ";
      return $h.=qq{realm="$_[0]{realm}"};
    }
  }

}


sub digest_parser{
  my $nonce;
  my $cnonce;
  my $opaque;
  my $domain;
  my $algorithm;
  my $realm;
  my $qop;
  my $userhash;
  my $charset;
  my $nc;
  my $response;

  my $secret;
  my $hash=sub{};
  my %params;
  sub {
    my ($info, $credentials)=@_;

    if($credentials){
      # Parse
      my @pairs=split ", ", $credentials;
      for (@pairs){
        my ($k,$v)=split "=";
        $v=~s/^"//;
        $v=~s/"$//;

        $params{$k}=$v;
      }

      # Find username, or at least hashed username from external
      #
      #
      my $username;

      # and get password
      #
      my $password;


      # Calculate server side
      my $A1;
      my $A2;
      if($params{algorithm}=~/-sess/){
        #A1 = H( unq(username) ":" unq(realm) ":" passwd ) ":" unq(nonce-prime) ":" unq(cnonce-prime)
      }
      else {
        #A1 = unq(username) ":" unq(realm) ":" passwd
        $A1=$hash->("$username:$realm:$password");

      }

      for($params{$qop}){
        if($_ eq "auth"){
          $A2="$_[REX][METHOD]:$_[REX][URI]";
        }
        elsif($_ eq "auth-int"){
          $A2="$_[REX][METHOD]:$_[REX][URI]:". $hash->($_[PAYLOAD]);
        }
        else {
          # error
        }
      }


      my $hash_A1=$hash->($A1);
      my $hash_A2=$hash->($A2);


      my $server_gen_response=$hash->("$hash_A1:"."$nonce:$nc:$cnonce:$qop:$hash_A2");
      #compare with what the client sent
      if($server_gen_response eq $response){
        #Authenticated
      }
      else {
        # Failed
        # #write the headers
      }
      $params{scheme}=$_[0]{scheme};
      $params{label}=$_[0]{label};
      # Write header
      #
      return \%params;
    }
    else {
      #Write out headers
    }
  }
}


sub bearer_parser {
  sub {
    my ($info, $credentials)=@_;
    my %params;
    if($credentials){
      %params=(
        token=>$_[1],
        realm=>$_[0]{realm},
        label=>$_[0]{label},
        scheme=>$_[0]{scheme}
      );
      return \%params;
    }
    else {
      #write header?
      my $h="Bearer ";
      return $h.=qq{realm="$_[0]{realm}"};
    }
  }
    
}

sub cookie_parser {
  sub {
    my ($info, $credentials)=@_;
    my %params;
    if($credentials){
      #parser
      %params=(
        token=>$_[1],
        label=>$_[0]{label},
        scheme=>$_[0]{scheme}
      );
      return \%params;
    }
    else {
      # serializer
      #write header?
      #Require a redirect?
      asay $STDERR, "NOTHING TO RETURN";
      return ();
    }
  }
}


sub uhm_login {
  my %options=@_;

  my $auth_cb=$options{auth_cb}//sub {};
  my $name=$options{name}//"SESSION_ID";
  
  (
    uhm_decode_form(),
    [
      sub {
        my ($next)=@_;
        sub {
          #process the form
          adump $STDERR, "post login", $_[PAYLOAD][0][PART_CONTENT];
          my $details=$_[PAYLOAD][0][PART_CONTENT];

          # Check the CSRF token is valid
          adump $STDERR, $details;

          my @args=@_;
          my @authenticated;

          my $cb= sub {
            # Called by auth_cb   with SERIALISED results
            push @authenticated, @_;
            unless(@authenticated){
              # Failed.. no session
              # only cookie header used. fail with redirect
              $_[REX][REDIRECT]=".";
              &rex_redirect_see_other;
            }
            else {
              # Got a result
              # set cookie
              push $args[OUT_HEADER]{HTTP_SET_COOKIE()}->@*, encode_set_cookie $name, $authenticated[0];

              $_[REX][REDIRECT]="/success";
              # redirect to target page
            }
            &rex_redirect_see_other;
            
          };

          
          for($details->{protection_token}){
            my $data=verify_protection_token($_);

            adump $STDERR, $data;

            if(defined $data){
              # Here we validate the content of the form
              # $details MUST BE A REF for checking and getting an encded repoonse
              $auth_cb->($details, $cb);
            }
            else {
              # Form is not permitted.. somehting bad
              &rex_error_forbidden;
            }

          }

        }
      }
    ]
  )
  # Middleware to generate a session
      
  # Expects a post request 
}

sub uhm_logout {
  # Middleware to end a sesssion

}

# Create a site/group
sub uhs_authenticate {
    #add a login/ and logout route
}

1;
