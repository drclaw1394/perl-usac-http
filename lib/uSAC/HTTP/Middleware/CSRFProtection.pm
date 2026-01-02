#
# Set two cookies of the same name, one with the __Host- prefix
# This will be accepted by the browser if secure and rejected otherwise
# Likewise it will only be sent back if secure
#
# If the prefixed cookie is present, only consider it.
# Otherwise, if enabled, continue processing non prefixed cookie?
#
# Other conditions for prefixed version to be accepted:
#   no domain in cookide (forces host only)
#   set path to  "/" (applicable to all path, not default for example)
#
#   name=__Host-CSRFToken value=... path=/ secure
#   name= CSRFToken value... path=/
#
# In case a cookie could fixated, the CSRFToken value should be derived from a
# session id  or similar.
# An attacker, then can not a CRSFToken from their session and set cookies in your session.
#
# 
#
use uSAC::HTTP ":constants";
use uSAC::HTTP::Route;
use List::Insertion {type=>numeric, duplicate=>"left", accessor=>"->[0]"};

use Export::These ("uhm_csrf");

sub uhm_csrf {

CONFIG:
  my %options=@_;
  # Name of header to generate on safe method
  my $header_name=$options{header_name}//"X-CSRF-Token";

  # Name of cookie to generate on safe method
  my $cookie_name=$options{cookie_name}//"_csrf_token";

  #  Max age (time out) of token
  #my $max_age=$options{max_age}//60;

  my $continue_on_fail;

  require HTTP::State::Cookie if $cookie_name;

  my $regex_filter;
  my $code_filter;

  for($options{content_filter}){
      if(ref eq "RegExp"){
        $regex_filter=$_;
      }
      elsif(ref eq "CODE") {
        $code_filter=$_;
      }
      else {
        die "Unsupported content filter in CSRFProtection";
      }
  }

  # This must be a sub reference
  my $token_generator=$options{token_generator};

  my %token_store; 

  use Data::UUID;
  my $ug = Data::UUID->new;

SUBS:
  # innerware creates a token for a get request and adds it to the
  # tracking list
  #
  [
    sub {
      my ($next, $index, %options)=@_;
      #my $field_name=$options{field_name}//"_csrf_token";
      sub {

        if($_[OUT_HEADER]){
            for($_[IN_HEADER]{":method"}){
              if(/^GET|^HEAD/){
                # Only generate the code on start of a safe request
                #
                my $token=$token_generator//$ug->create_b64();

                # Store expiry
                $token_store{$token}=time+$max_age;
                

                # Add to output headers if enabled
                #
                $_[OUT_HEADER]{$header_name}=$token if $header_name;

                # Set cookie if enabled
                push $_[OUT_HEADER]{":state"}->@*, HTTP::State::Cookie::cookie_struct($cookie_name, $token, "max-age"=>$max_age, httponly=>1) if $cookie_name;

                # Also add to psuedo header for middelware to access?
                $_[OUT_HEADER]{":csrf_token"}=$token;
              }


              elsif(/^POST|^PUT|^DELETE/){
                # We are expecting a token from the client somewhere
                # the headers. Either custom header or in cookie
                my $token;

                if($header_name){
                  # Expecting token returned in header.
                  $token= $_[IN_HEADER]{$header_name};

                  my $time;
                  $time=delete $token_store{$token} if $token;

                  if($time and $time < time){
                    $_[IN_HEADER]{":csrf_token"}=undef;
                    $_[REX][STATUS]=HTTP_NOT_AUTHORIZED;

                    # Expired or did not exists in the first place
                    $continue_on_fail
                      ? return &$next
                      : return $_[ROUTE][1][ROUTE_SERIALIZE]->&*;
                  }
                }
                elsif($cookie_name){
                  # We don't know what the token is. User program must parse
                  # and then do a lookup
                  $_[IN_HEADER]{":csrf_lookup"}=\%token_store;
                }

                else {
                }

              }
              else {
                #Assume ok to continue
                &$next;
              }
          }
          
        }
        &$next;
      } 
    },

    sub {
      my ($next, $index,%options)=@_;
      sub {
        # Header is rendered automatically
        # cookie is rendered automatically
        #
        # Content filter needs to be hookied
        #
        $_[PAYLOAD]=~s/$regex_filter/$token/ if $regex_filter;
        &$code_filter if $code_filter;
        &$next;
      }
    },

    undef
  ]
};
1;

=head1 NAME

U:H:M:CSRFProtection - Protect against CSRF Attacks

=head1 DESCRIPTION

With the adevent of samesite cookie processing, CSRF mitigation is made largely
easier. However there are still cases where active protection is required.



=head1 What does this module do?

It generates a CSRF token on a safe method (ie get or head) and stores it in a
database. If the headername option was provided, the a header is added to the
output headers.  if cookie name is provided, the as set cookie is added to the
:state output header
If content filter is provided (rexexp or subroutine ref), this  is called with the value to perform substitution on the payload in the outerware phase


=head2 CSRF Background

A Cross Site Request Forgery attack is when a cross site (third party site or actor) can issue requests on your behalf to a site of intrest.

The forged request uses credentials (session ID) stored in the browser, which is automaticall sent to the target site on every request.

Same site suppory largely prevents this from happeding however, there are cases where this isn't enough.

=over 

=item subdomains?

A sub domain can set 

=item multiple users on the same site

A malicious link published on a public page, to the same origin, will still
have the session cookie sent. This requires seconary methods of ensuring the
request indeed was authentic and not forged


=head1 Mitigation Techniques

=head2 HTML Body Content

Somewhere in the content of the HTML response, a CSRF token can be added to the
DOM. 

=head3 HTML Form submition

This can easiliy be added as a hidden form element when presenting a form. When
posting the field is send automatically. The server side needs to process the
form and compare the token to the expected value.

No javascript is required. The form does need to be dynamically created.


=head3 Other DOM location

Other than a form, any dom element accessable with javascript can be configured
to have the CSRF token.  This requires javascript to retrieve the value and to
issue a AJAX request. DOM elements could be a meta tag, or hidden div, or
justabout anything you like.

Requires javascript. This is subject to same origin policy and CORS


=head2 HTTP Headers

=head3 Custom Headers

A custom header could be set by the server 

=head3 Set-Cookie

Double submit cookie technique





=back

