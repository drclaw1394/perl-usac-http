use v5.36;
package uSAC::HTTP::Form;

use URL::Encode qw<url_decode_utf8>;

use Export::These qw<decode_urlencoded_form>;

sub decode_urlencoded_form {
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

1;
