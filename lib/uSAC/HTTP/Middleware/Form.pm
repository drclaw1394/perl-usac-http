use v5.36;
package uSAC::HTTP::Middleware::Form;

use Cpanel::JSON::XS;

use uSAC::HTTP;

use URL::Encode qw<url_decode_utf8>;

use Export::These qw<decode_urlencoded_form uhm_decode_form>;

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
        use Data::Dumper;
        use uSAC::IO;

# Basic wrapper to simply give the key value pairs from slurped url
# encoded form
sub uhm_decode_form {

  require uSAC::HTTP::Middleware::Multipart;
  require uSAC::HTTP::Middleware::Slurp;
  (
    uSAC::HTTP::Middleware::Multipart::uhm_multipart(),     # process multipart if applicable,
    
    uSAC::HTTP::Middleware::Slurp::uhm_slurp(),             # Slurp the contents into memory or files
                                                            # Also makes a single part if required

    sub { 
      # Prcess all parts of the upload, using the content disposition header
      for my $part ($_[PAYLOAD]->@*){
        my $ph=$part->[0];
        for($part->[0]{'content-type'}){

          if($_ eq "application/x-www-form-urlencoded"){
            # this is a special case where the main header content type has been copied into the 'part'
            $part->[1]=decode_urlencoded_form $part->[1]  ;
          }
          elsif($_ eq "application/json"){
            $part->[1]=decode_json $part->[1];
          }
        }
      }
      1;
    },
  );
}


1;
