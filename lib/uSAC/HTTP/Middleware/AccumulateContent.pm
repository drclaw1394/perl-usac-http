package uSAC::HTTP::Middleware::AccumulateContent;
use warnings;
use strict;
use feature qw<current_sub say refaliasing state>;
no warnings "experimental";
our $UPLOAD_LIMIT=1_000_000;
our $PART_LIMIT=$UPLOAD_LIMIT;
use Log::ger;

use Log::OK;
use uSAC::HTTP::Code qw<:constants>;
use uSAC::HTTP::Header qw<:constants>;
use uSAC::HTTP::Constants;
use uSAC::HTTP::Rex;
use uSAC::HTTP::Route;
use IO::FD;
use Fcntl qw<O_CREAT O_RDWR>;
use File::Spec::Functions qw<catfile>;

use Exporter 'import';

use URL::Encode::XS;
use URL::Encode qw<url_decode_utf8>;
use Cpanel::JSON::XS qw<encode_json decode_json>;

our @EXPORT_OK=qw<
  uhm_urlencoded_slurp
  uhm_urlencoded_file
  uhm_multipart_slurp
  uhm_multipart_file
  uhm_slurp
>;

our @EXPORT=@EXPORT_OK;

#Innerware which aggrigates the streaming url encoded body content
sub uhm_urlencoded_slurp {

  my %options=@_;
	my $upload_limit=$UPLOAD_LIMIT;
  $upload_limit = $options{byte_limit} if exists $options{byte_limit};
  my $content_type=$options{content_type}//"application/x-www-form-urlencoded";
   
  my %ctx;
  my $inner=sub {
    my $next=shift;
    sub {
    #This sub is shared across all requests for  a route. 
      my $c;
      if($_[OUT_HEADER]){
        #test incomming headers are correct
        
        #unless(($_[REX]->headers->{CONTENT_TYPE}//"") =~ /$content_type/){ #m{application/x-www-form-urlencoded}){
        unless(($_[IN_HEADER]{HTTP_CONTENT_TYPE()}//"") =~ /$content_type/){ #m{application/x-www-form-urlencoded}){
          $_[PAYLOAD]="";
          say "accumuate UNSPPORTED";
          return &rex_error_unsupported_media_type 
        }

        #$content_length=$_[REX]->headers->{CONTENT_LENGTH};
        #if(defined $upload_limit  and ($_[REX]->headers->{CONTENT_LENGTH}//0) > $upload_limit){
        if(defined $upload_limit  and ($_[IN_HEADER]{HTTP_CONTENT_LENGTH()}//0) > $upload_limit){
          $_[OUT_HEADER]{":status"}=HTTP_PAYLOAD_TOO_LARGE;
          $_[PAYLOAD]="";#"Slurp Limit:  $upload_limit";
          say "accumulate do big";
          return &rex_error;
        }

        #first call
        $_[REX][uSAC::HTTP::Rex::in_progress_]=1;
        $c=$ctx{$_[REX]}=[{},$_[PAYLOAD]]; #First call stores the payload
        $c->[0]{_byte_count}=0;
      }
      else{
        #subsequent calls
        $c=$ctx{$_[REX]};
        $c->[1].=$_[PAYLOAD];
        $c->[0]{_byte_count}+=length $_[PAYLOAD];
      }

      #Check total incomming byte count is within limits
      ##only needed for chunks?
      if(defined $upload_limit  and $c->[0]{_byte_count} > $upload_limit){
        $_[OUT_HEADER]{":status"}=HTTP_PAYLOAD_TOO_LARGE;
        $_[PAYLOAD]="";#"Slurp Limit:  $upload_limit";
        return &rex_error;
      }

      #Accumulate until the last
      if(!$_[CB]){
        #Last set
        $_[PAYLOAD]=$c->[1];
        delete $ctx{$_[REX]};
        undef $c;
        &$next;
      }
    }
  };

  my $outer=sub {
    my $next=shift;
  };

  my $error=sub {
    my $next=shift;
    sub {
        delete $ctx{$_[REX]};
        &$next;
    }
  };

  [$inner, $outer, $error];
}

sub uhm_urlencoded_file {

  my %options=@_;
  #my $upload_dir=$options{upload_dir};
  my $upload_dir=$options{upload_dir}; 
	my $upload_limit=$options{byte_limit}//$UPLOAD_LIMIT;

  my %ctx;
  my $inner=sub {
    my $next=shift;
    sub {
      #This sub is shared across all requests for  a route. 
      say STDERR "URL UPLOAD TO FILE";
      my $c;
      if($_[OUT_HEADER]){
        #unless($_[REX]->headers->{CONTENT_TYPE} =~ m{application/x-www-form-urlencoded}){
        unless($_[IN_HEADER]{HTTP_CONTENT_TYPE()} =~ m{application/x-www-form-urlencoded}){
          $_[PAYLOAD]="";
          return &rex_error_unsupported_media_type 
        }
        #if(defined $upload_limit  and $_[REX]->headers->{CONTENT_LENGTH} > $upload_limit){
        if(defined $upload_limit  and $_[IN_HEADER]{HTTP_CONTENT_LENGTH()} > $upload_limit){
          $_[OUT_HEADER]{":status"}=HTTP_PAYLOAD_TOO_LARGE;
          $_[PAYLOAD]="Limit:  $upload_limit";
          return &rex_error;
        }
        say STDERR "URL UPLOAD TO FILE first call";
        #first call. Open file a temp file
        my $path=IO::FD::mktemp catfile $upload_dir, "X"x10;
        say STDERR "URL UPLOAD TO FILE first call: path is $path";
        my $error;

        if(defined IO::FD::sysopen( my $fd, $path, O_CREAT|O_RDWR)){
          #store the file descriptor in the body field of the payload     
          my $bytes;
          if(defined ($bytes=IO::FD::syswrite $fd, $_[PAYLOAD])){
            $_[PAYLOAD][0]{_filename}=$path;
            $_[PAYLOAD][0]{_byte_count}=$bytes;
            $_[PAYLOAD][1]=$fd;
          }
          else {
            say STDERR "ERROR writing FILE $!";
            &rex_error_internal_server_error;
            #Internal server error
          }
        }
        else {
            #Internal server error
            say STDERR "ERROR OPENING FILE $!";
            &rex_error_internal_server_error;
        }

        $_[REX][uSAC::HTTP::Rex::in_progress_]=1;
        $c=$ctx{$_[REX]}=[{},undef];
      }
      else{
        #subsequent calls
        $c=$ctx{$_[REX]};
        my $bytes;
        if(defined($bytes=IO::FD::syswrite $c->[1], $_[PAYLOAD])){
          $c->[0]{_byte_count}+=$bytes;

        }
        else {
          #internal server error
            &rex_error_internal_server_error;
        }

      }

      #Check file size is within limits
      if(defined $upload_limit  and $c->[0]{_byte_count} > $upload_limit){
        $_[OUT_HEADER]{":status"}=HTTP_PAYLOAD_TOO_LARGE;
        $_[PAYLOAD]="Limit:  $upload_limit";
        return &rex_error;
      }


      #Accumulate until the last
      if(!$_[CB]){
        #Last set
        my $c=$_[PAYLOAD]=delete $ctx{$_[REX]};
        if(defined IO::FD::close $c->[1]){
          
        }
        else {
          #Internal server error
        }
        $c->[1]=undef;
        &$next;
      }
        

    }
  };

  my $outer=sub {
    my $next=shift;
  };
  
  my $error=sub {
    my $next=shift;
    sub {
        delete $ctx{$_[REX]};
        &$next;
    }
  };

  [$inner, $outer, $error];

}



# Slurp multipart and emit a single payload on completion
sub uhm_multipart_slurp {

  my %options=@_;
  #if a upload directory is specified, then we write the parts to file instead of memory
  #
  my %ctx;
  my $inner=sub {
    my $next=shift;
    my $last;
    sub {
      say STDERR " slurp multipart MIDDLEWARE";
        my $c=$ctx{$_[REX]};

        unless($c){
          $c=$ctx{$_[REX]}=[$_[PAYLOAD]];
          $_[REX][uSAC::HTTP::Rex::in_progress_]=1;
        }
        else {
          #For each part (or partial part) we need to append to the right section
          $last=@$c-1;
          # Compare header hashes by reference
          if($_[PAYLOAD][0] == $c->[$last][0]){
            #Header information is the same. Append data
            $c->[$last][1].=$_[PAYLOAD][1];
          }
          else {
            #New part
            push @$c, $_[PAYLOAD];
          }
        }

        #Call next only when accumulation is done
        #Pass the list to the next
        unless($_[CB]){
          $_[PAYLOAD]=delete $ctx{$_[REX]};
          &$next;
        }
    }
  };

  my $outer=sub {
    my $next=shift;
  };

  my $error=sub {
    my $next=shift;
    sub {
        delete $ctx{$_[REX]};
        &$next;
    }
  };

  [$inner, $outer, $error];
}

# Have a filter of field names which are to be stored to disk?
sub uhm_multipart_file {
  my %options=@_;
  #my $upload_dir=$options{upload_dir};
  my $upload_dir=$options{upload_dir}; 

  my %ctx;
  my $inner=sub {
    my $next=shift;
    my $last;
    sub {
      say STDERR " file multipart MIDDLEWARE";
        my $open;
        my $c=$ctx{$_[REX]};
        unless($c){
          #first call
          $c=$ctx{$_[REX]}=[];
          $_[REX][uSAC::HTTP::Rex::in_progress_]=1;

        }
          #For each part (or partial part) we need to append to the right section
          #$c=$ctx{$_[REX]};
          $last=@$c-1;
          if(@$c and $_[PAYLOAD][0] == $c->[$last][0]){
            #Header information is the same. Append data
            my $fd=$c->[$last][1];
            if(defined IO::FD::syswrite $fd, $_[PAYLOAD][1]){
              #not used
            }
          }

          else {
            #New part

            #close old one
            IO::FD::close $c->[$last][1] if @$c;

            #open new one
            my $path=IO::FD::mktemp catfile $upload_dir, "X"x10;
            my $error;

            if(defined IO::FD::sysopen( my $fd, $path, O_CREAT|O_RDWR)){
              #store the file descriptor in the body field of the payload     
              if(defined IO::FD::syswrite $fd, $_[PAYLOAD][1]){
                $_[PAYLOAD][0]{_filename}=$path;
                $_[PAYLOAD][1]=$fd;
                push @$c, $_[PAYLOAD][0];
              }
              else {
                say STDERR "ERROR writing FILE $!";
                &rex_error_internal_server_error;
                #Internal server error
              }
            }
            else {
              #Internal server error
              say STDERR "ERROR OPENING FILE $!";
              &rex_error_internal_server_error;
            }
          }


        #Call next only when accumulation is done
        #Pass the list to the next
        unless($_[CB]){
            #close old one
            IO::FD::close $c->[$last][1] if @$c;
          $_[PAYLOAD]=delete $ctx{$_[REX]};
          &$next;
        }
      }
  };

  my $outer=sub {
    my $next=shift;
  };
  
  my $error=sub {
    my $next=shift;
    sub {
        delete $ctx{$_[REX]};
        &$next;
    }
  };

  [$inner, $outer, $error];
}




# Converts partial incomming data into a stream of completed items
sub uhm_slurp {
  my %options=@_;
  
  my $upload_dir=$options{upload_dir}//"uploads";
	my $upload_limit=$options{byte_limit}//$UPLOAD_LIMIT;
  my $close_on_complete=$options{close_on_complete};


  my $fields_to_file=$options{fields_to_file}//[];   #list of field names to store to disk

  my %ctx;
  my $inner=sub {
    my $next=shift;
    my $last;
    sub {
    #say STDERR " slurp multipart MIDDLEWARE";
      #say STDERR Dumper $_[PAYLOAD];
        my $open;
        my $c=$ctx{$_[REX]};
        unless($c){
          #first call, create a new context
          $c=$ctx{$_[REX]}=[];
          $_[REX][uSAC::HTTP::Rex::in_progress_]=1;

        }


        my $payload=$_[PAYLOAD];
        my $cb=$_[CB];
        $_[PAYLOAD]="";
        # Check for Expect header and respond if needed to
        if($_[IN_HEADER]{HTTP_EXPECT()}){
          # Bypass and write a 100 reponse 
          my $header=$_[OUT_HEADER];
          $_[OUT_HEADER]{":status"}=HTTP_CONTINUE;
          $_[CB]=sub {say "callback dummy for slurp";};
          $_[ROUTE][1][ROUTE_OUTER_HEAD]->&*;
          return unless $payload;
        }
        # Restore callback after CONTINUE
        #
        $_[CB]=$cb;
        # Wrap payload if need be 
        unless(ref $payload){
          $payload=[{}, $payload];
        }
          #For each part (or partial part) we need to append to the right section
          #$c=$ctx{$_[REX]};
          $last=@$c-1;
          if(@$c and $payload->[0] == $c->[$last][0]){
            #Header information is the same. Append data
            if($c->[$last][0]{_filename}){
              my $fd=$c->[$last][1];
              if(defined IO::FD::syswrite $fd, $payload->[1]){
                #not used
              }
            }
            else {
              $c->[$last][1].=$payload->[1];
            }
          }

          else {
            #New part

            #close old one
            IO::FD::close $c->[$last][1] if @$c and $c->[$last][0]{_filename} and $close_on_complete;

            #open new one
            my $h=$payload->[0];

            if($h->{_filename}){
              my $path=IO::FD::mktemp catfile $upload_dir, "X" x 10;
              my $error;

              if(defined IO::FD::sysopen(my $fd, $path, O_CREAT|O_RDWR)){
                #store the file descriptor in the body field of the payload     

                if(defined IO::FD::syswrite $fd, $payload->[1]){
                  $payload->[0]{_path}=$path;
                  $payload->[1]=$close_on_complete?undef:$fd;
                  push @$c, $payload;
                }
                else {
                  say STDERR "ERROR writing FILE $!";
                  &rex_error_internal_server_error;
                  #Internal server error
                }
              }
              else {
                #Internal server error
                say STDERR "ERROR OPENING FILE $!";
                &rex_error_internal_server_error;
              }
            }
            else {
              # Append into memory
              push @$c, $payload;
            }
             

          }


        #Call next only when accumulation is done
        #Pass the list to the next
        unless($_[CB]){
            #close old one
            IO::FD::close $c->[$last][1] if @$c and $c->[$last][0]{_filename} and $close_on_complete;
          $_[PAYLOAD]=delete $ctx{$_[REX]};
          &$next;
        }
      }
  };

  my $outer=sub {
    my $next=shift;
  };
  
  my $error=sub {
    my $next=shift;
    sub {
        my $c=delete $ctx{$_[REX]};
        for (@$c){
          #Force close any file descriptors
          #
          IO::FD::close $_->[1] if $_->[0]{_filename};
        }
        
        &$next;
    }
  };

  [$inner, $outer, $error];
}

