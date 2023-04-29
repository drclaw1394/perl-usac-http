package uSAC::HTTP::Middleware::AccumulateContent;
use warnings;
use strict;
use feature qw<current_sub say refaliasing state>;
no warnings "experimental";
our $UPLOAD_LIMIT=1000;
our $PART_LIMIT=$UPLOAD_LIMIT;
use Log::ger;

use Log::OK;
use uSAC::HTTP::Code qw<:constants>;
use uSAC::HTTP::Header qw<:constants>;
use uSAC::HTTP::Constants;
use IO::FD;
use Fcntl qw<O_CREAT O_RDWR>;

use Exporter 'import';

use URL::Encode::XS;
use URL::Encode qw<url_decode_utf8>;
use Cpanel::JSON::XS qw<encode_json decode_json>;

our @EXPORT_OK=qw<
  uhm_urlencoded_slurp
  uhm_urlencoded_file
  uhm_multipart_slurp
  uhm_multipart_file
>;

our @EXPORT=@EXPORT_OK;

#Innerware which aggrigates the streaming url encoded body content
sub uhm_urlencoded_slurp {

  my %options=@_;
	my $upload_limit=$options{byte_limit}//$UPLOAD_LIMIT;
  my $content_type=$options{content_type}//"application/x-www-form-urlencoded";
   
  my $inner=sub {
    my $next=shift;
    my %ctx;
    sub {
      #This sub is shared across all requests for  a route. 
      if($_[CODE]){
        my $c;
        if($_[HEADER]){
          #test incomming headers are correct
          
          unless(($_[REX]->headers->{CONTENT_TYPE}//"") =~ /$content_type/){ #m{application/x-www-form-urlencoded}){
            $_[PAYLOAD]="adsfasdf";
			      return &rex_error_unsupported_media_type 
          }
          #$content_length=$_[REX]->headers->{CONTENT_LENGTH};
          if(defined $upload_limit  and ($_[REX]->headers->{CONTENT_LENGTH}//0) > $upload_limit){
            #@err_res=(HTTP_PAYLOAD_TOO_LARGE, [], "limit: $upload_limit");
            $_[CODE]=HTTP_PAYLOAD_TOO_LARGE;
            #$_[HEADER]=[];
            $_[HEADER]={};
            $_[PAYLOAD]="Slurp Limit:  $upload_limit";
            return &rex_error;
          }

          #first call
          $_[REX][uSAC::HTTP::Rex::in_progress_]=1;
          $c=$ctx{$_[REX]}=$_[PAYLOAD];
          $_[PAYLOAD][0]{_byte_count}=0;
        }
        else{
          #subsequent calls
          $c=$ctx{$_[REX]};
          $c->[1].=$_[PAYLOAD][1];
          $c->[0]{_byte_count}+=length $_[PAYLOAD][1];
        }

        #Check total incomming byte count is within limits
        ##only needed for chunks?
        if(defined $upload_limit  and $c->[0]{_byte_count} > $upload_limit){
          $_[CODE]=HTTP_PAYLOAD_TOO_LARGE;
          #$_[HEADER]=[];
            $_[HEADER]={};
          $_[PAYLOAD]="Slurp Limit:  $upload_limit";
          return &rex_error;
        }

        #Accumulate until the last
        if(!$_[CB]){
          #Last set
          $_[PAYLOAD]=[delete $ctx{$_[REX]}];
          undef $c;
          &$next;
        }
        
      }
      else {
        delete $ctx{$_[REX]};
        &$next;
      }

    }
  };

  my $outer=sub {
    my $next=shift;
  };

  [$inner, $outer];

}
sub uhm_urlencoded_file {

  my %options=@_;
  #my $upload_dir=$options{upload_dir};
  my $upload_dir=$options{upload_dir}; 
	my $upload_limit=$options{byte_limit}//$UPLOAD_LIMIT;

  my $inner=sub {
    my $next=shift;
    my %ctx;
    sub {
      #This sub is shared across all requests for  a route. 
      say STDERR "URL UPLOAD TO FILE";
      if($_[CODE]){
        my $c;
        if($_[HEADER]){
          unless($_[REX]->headers->{CONTENT_TYPE} =~ m{application/x-www-form-urlencoded}){
            $_[PAYLOAD]="";
			      return &rex_error_unsupported_media_type 
          }
          #$content_length=$_[REX]->headers->{CONTENT_LENGTH};
          if(defined $upload_limit  and $_[REX]->headers->{CONTENT_LENGTH} > $upload_limit){
            #@err_res=(HTTP_PAYLOAD_TOO_LARGE, [], "limit: $upload_limit");
            $_[CODE]=HTTP_PAYLOAD_TOO_LARGE;
            #$_[HEADER]=[];
            $_[HEADER]={};
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
            if(defined ($bytes=IO::FD::syswrite $fd, $_[PAYLOAD][1])){
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
          $c=$ctx{$_[REX]}=$_[PAYLOAD];
        }
        else{
          #subsequent calls
          $c=$ctx{$_[REX]};
          my $bytes;
          if(defined($bytes=IO::FD::syswrite $c->[1], $_[PAYLOAD][1])){
            $c->[0]{_byte_count}+=$bytes;

          }
          else {
            #internal server error
              &rex_error_internal_server_error;
          }

        }

        #Check file size is within limits
        if(defined $upload_limit  and $c->[0]{_byte_count} > $upload_limit){
          $_[CODE]=HTTP_PAYLOAD_TOO_LARGE;
          #$_[HEADER]=[];
          $_[HEADER]={};
          $_[PAYLOAD]="Limit:  $upload_limit";
          return &rex_error;
        }


        #Accumulate until the last
        if(!$_[CB]){
          #Last set
          my $c=$_[PAYLOAD]=[delete $ctx{$_[REX]}];
          if(defined IO::FD::close $c->[0][1]){
            
          }
          else {
            #Internal server error
          }
          $c->[0][1]=undef;
          &$next;
        }
        
      }
      else {
        #At this point the connection should be closed
        my $c=delete $ctx{$_[REX]};
        if($c->[1]){
          #Force close fds
          IO::FD::close $c->[1];
        }
        &$next;
      }

    }
  };

  my $outer=sub {
    my $next=shift;
  };

  [$inner, $outer];

}




sub uhm_multipart_slurp {

  my %options=@_;
  #if a upload directory is specified, then we write the parts to file instead of memory
  #
  my $inner=sub {
    my $next=shift;
    my %ctx;
    my $last;
    sub {
      say STDERR " slurp multipart MIDDLEWARE";
      if($_[CODE]){
        my $c=$ctx{$_[REX]};
        unless($c){
          $c=$ctx{$_[REX]}=[$_[PAYLOAD]];
          $_[REX][uSAC::HTTP::Rex::in_progress_]=1;
        }
        else {
          #For each part (or partial part) we need to append to the right section
          #$c=$ctx{$_[REX]};
          $last=@$c-1;
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
      else {
        delete $ctx{$_[REX]};
        &$next;
      }
    }
  };

  my $outer=sub {
    my $next=shift;
  };

  [$inner,$outer];
}
sub uhm_multipart_file {

  my %options=@_;
  #my $upload_dir=$options{upload_dir};
  my $upload_dir=$options{upload_dir}; 

  my $inner=sub {
    my $next=shift;
    my %ctx;
    my $last;
    sub {
      say STDERR " file multipart MIDDLEWARE";
      if($_[CODE]){
        my $open;
        my $c=$ctx{$_[REX]};
        unless($c){
          #first call
          $c=$ctx{$_[REX]}=[];#$_[PAYLOAD]];
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
                push @$c, $_[PAYLOAD];
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
      else {
        delete $ctx{$_[REX]};
        &$next;
      }
    }
  };

  my $outer=sub {
    my $next=shift;
  };

  [$inner,$outer];
}

