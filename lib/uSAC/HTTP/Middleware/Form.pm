use v5.36;
package uSAC::HTTP::Middleware::Form;



use uSAC::HTTP;

use URL::Encode qw<url_decode_utf8>;
use constant::more qw<PART_HEADER=0 PART_CONTENT>;

use Export::These qw<decode_urlencoded_form uhm_decode_form generate_protection_token verify_protection_token PART_HEADER PART_CONTENT>;

use UUID qw<uuid4>;
use Crypt::JWT ":all";


# Stores the count of each form CSRF token instance.

my %valid;

# Ever changing secrets.
#
my $secret=uuid4();
my $prev_secret=uuid4();

my $timer=uSAC::IO::timer 0, 10, sub {
  # The csrf values are invalidated when on updating the secret (twice)
  # All the csrf values are keyed by the secret value used.  So simply delete the
  # has entry minimuse state storage
  #
  delete $valid{$prev_secret};
  $prev_secret=$secret;
  $secret=uuid4();
};

##########################################
# my $timer2=uSAC::IO::timer 0, 1, sub { #
#   adump $STDERR ,\%valid;              #
# };                                     #
##########################################

uSAC::Main::usac_listen("server/shutdown/graceful", sub { 
  uSAC::IO::timer_cancel $timer; 
  #uSAC::IO::timer_cancel $timer2; 
});


# the argument is is the payload for a jwt.
# The reurned value is the value to be added to a form
#
sub generate_protection_token {
  my $data=shift;

  my $timeout=shift//5*60; # five minutes

  my $csrf_token = uuid4(); 

  my $limit=shift//1;

  my $hidden={
    csrf    =>  $csrf_token,
    counter =>  $limit,
    limit   =>  $limit,
    timeout =>  $timeout,
    create  =>  time,
    data    =>  $data,
  };

  $valid{$secret}{$csrf_token}=$limit;

  my $jwt=encode_jwt(payload=>$hidden, alg=>'HS256', key=>$secret);
}

# Return data if it passes verification checks
sub verify_protection_token {

    my $token=shift;
    asay $STDERR, "verify token";
    adump $STDERR, $token;
    my $jwt;
    
    my $key;
    $jwt=eval {decode_jwt(token=>$token, key=>$secret)};
    if($jwt){
      $key=$secret
    }
    else {
     $jwt=eval {decode_jwt(token=>$token, key=>$prev_secret)};
      $key=$prev_secret;
    }

    return unless $jwt;



    my $pass=1;
    # Check if checksum matches. Discontinue processing if checksum fails
    #
    $pass&&=1;

    return undef unless $pass;

    #Check if expired or replays reached
    #
    my $csrf=$jwt->{csrf};
    my $entry=$valid{$key};
    for($entry->{$csrf}){
      if(defined
          and $jwt->{expires} <= time 
          and ($_ > 0
        )){

        # Within limit and not expired yet. Decrement count
        $_-- if $_;

        delete $entry->{$csrf};
        return $jwt->{data};
      }
      else {
        # Limit reached or maybe expired or doesn't exist
        asay $STDERR, "Limit Reached or expired... removing ";
        delete $entry->{$csrf};
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
            require Cpanel::JSON::XS;
            $part->[1]=Cpanel::JSON::XS::decode_json $part->[1];
          }
        }
      }
      1;
    },
  );
}


1;
