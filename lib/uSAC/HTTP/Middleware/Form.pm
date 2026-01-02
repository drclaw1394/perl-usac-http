use v5.36;
package uSAC::HTTP::Middleware::Form;

use Cpanel::JSON::XS;

use uSAC::HTTP;

use URL::Encode qw<url_decode_utf8>;

use Export::These qw<decode_urlencoded_form uhm_decode_form generate_protection_token verify_protection_token>;

use UUID qw<uuid4>;
use Crypt::JWT ":all";

# Stores the count of each form instance
#
my %submit_count;

# Internal secret to for signing
my $secret=uuid4();


# the argument is is the payload for a jwt.
# The reurned value is the value to be added to a form
#
sub generate_protection_token {
  my $data=shift;


  my $timeout=shift//5*60; # five minutes

  my $csrf_token = uuid4(); 


  my $limit=shift//1;
  if($limit){
    # track the tocken only if we set a limit
    $submit_count{$csrf_token}=$limit;
  }

  my $hidden={
    csrf=>$csrf_token,
    expires=>$timeout,
    data=>$data,
  };

  my $jwt=encode_jwt (payload=>$hidden, alg=>'HS256', key=>$secret);
}

# Return data if it passes verification checks
sub verify_protection_token {

    my $token=shift;
    asay $STDERR, "verify token";
    adump $STDERR, $token;
    my $jwt=decode_jwt(token=>$token, key=>$secret);

    my $pass=1;
    # Check if checksum matches. Discontinue processing if checksum fails
    #
    $pass&&=1;

    return undef unless $pass;

    #Check if expired or replays reached
    #

    for($submit_count{$jwt->{csrf}}){
      if($jwt->{expires} <= time 
          and (!defined $_ or $_ > 0
        )){
        # Within limit and not expired yet

        $_-- if $_;

        return $jwt->{data};
      }
      else {
        # Limit reached or maybe expired
        asay $STDERR, "Limit Reached or expired... removing ";
        delete $submit_count{$jwt->{csrf}};
        return undef;
      }
    }
}


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
