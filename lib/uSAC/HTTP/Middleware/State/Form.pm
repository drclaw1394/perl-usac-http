=head1 TITLE

  HTML::State -  Store state in HTML Forms (body and query), without cookies


=head1 DESCRIPTION

Decodes HTTP Form data from request bodies and query parametesrs, extract the named field
and stores it in the REX state under the same name.


  (Multipart -> Slurp -> Form Decode )->  State Form    -> History
                                          State Cookie  -> History

=cut



package uSAC::HTTP::Middleware::State::Form;

use 5.036000;
use uSAC::HTTP;
use uSAC::HTTP::Rex;
use uSAC::HTTP::Middleware::Form;
use Cpanel::JSON::XS;
use MIME::Base64;
use uSAC::IO;
use Data::Dumper;


use Export::These qw<uhm_state_form encode_html_state_from>;
# Encodes state in application page (html) using a global form.
# The middleware extracts the state into the parameters
# Templates must render the state as a hiddin input

my $defualt_name="state_asdfasdf";
sub uhm_state_form{
  my %options=@_;

  my $name=$options{name}//$defualt_name;
  
  # Pass in the hash that has the named variable (ie $_[REX][STATE])
  sub encode_html_state_from_old {
    my $hash=$_[0]//{$name=>{}};
    
    # Expects the argument to be a hash which the name will we looked for 
    # Outputs a hidden input element with the name of the state
   
    #adump $STDERR, "enoding html state for input ", $hash;
    return qq{<input type="text" name="$name" size="100" value="@{[MIME::Base64::encode_base64url encode_json $hash->{$name}//{}]}">};
  }

  sub encode_html_state_from{
    my $hash=$_[0]//{$name=>{}};
    say STDERR "encoding html state  input is ", Dumper $hash;
    return MIME::Base64::encode_base64url encode_json $hash->{$name}//{};
  }


  (
    [ 
      # inner
      sub {
        my ($next)=@_;
        sub {
          # Decode query if not decoded
          for($_[REX][QUERY]||()){
            adump $STDERR, "URL is $_[REX][URI]";
            adump $STDERR, "Query is", $_;
              $_=decode_urlencoded_form $_ unless ref;
            adump $STDERR, "decoded query is", $_;

              for($_->{$name}){
                # Continue decoding into scratch
                #
                try {
                  $_[REX][STATE]{$name}=decode_json MIME::Base64::decode_base64url $_;
                }
                catch($e){
                  adump $STDERR, "Error in decoding state ", $e;
                  $_[REX][STATE]{$name}={};
                }
                # Set in scratch for use in rest of application
              }
          }


          if(ref $_[PAYLOAD]){
            adump $STDERR , "--- USING PAYLOAD TO UPDATE STATE-- ", $_[PAYLOAD];
            # this decodedd payload from previous middlware or even redirect internal
            my $d=$_[PAYLOAD][0][PART_CONTENT];
            
            my $post_state=$d->{$name};
            adump $STDERR, "POST HTML STATE DATA for $name", $d;
            $_[REX][STATE]{$name}=decode_json MIME::Base64::decode_base64url $post_state;

            
            ###################################################################################
            # for($_[REX][QUERY]){                                                            #
            #   $_=decode_urlencoded_form $_ unless ref;                                      #
            #   # Set the state parameter                                                     #
            #   $_[REX][STATE]{$name}=decode_json MIME::Base64::decode_base64url $post_state; #
            # }                                                                               #
            ###################################################################################
          }

          &$next;
        }
      }
    ]
  )
}


1;
