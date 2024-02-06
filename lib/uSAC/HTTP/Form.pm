use v5.36;
package uSAC::HTTP::Form;

use uSAC::HTTP;
use URL::Encode qw<url_decode_utf8>;

use Export::These qw<decode_urlencoded_form>;

sub decode_urlencoded_form {
  return undef unless $_[0];
  my %kv;
  for(split "&", url_decode_utf8 $_[0]){
    my ($k, $v)=split "=", $_, 2;
    if(!exists $kv{$k}){
        $kv{$k}=$v;
    }
    elsif(ref $kv{$k}){
      push $kv{$k}->@*, $v;
    }
    else {
      $kv{$k}=[$kv{$k}, $v];
    }
  }
  \%kv;
}

# Basic wrapper to simply give the key value pairs from slurped url
# encoded form
sub uhm_urlencoded_form {
  require uSAC::HTTP::Middleware::Slurp;
  (
    uSAC::HTTP::Middleware::Slurp::uhm_slurp(),
    sub { 
      $_[PAYLOAD]=decode_urlencoded_form $_[PAYLOAD][0][1];
      $_[PAYLOAD]//="";
      1;
    }
  )
}

sub uhm_multipart_form {
  require uSAC::HTTP::Middleware::Slurp;
  (
    uSAC::HTTP::Middleware::Slurp::uhm_slurp(),
    sub { 
      #TODO: Pass through currently
      1;
    }
  )
}

1;
