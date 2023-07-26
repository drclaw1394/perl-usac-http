package uSAC::HTTP::Middleware::Slurp;
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


use URL::Encode::XS;
use URL::Encode qw<url_decode_utf8>;
use Cpanel::JSON::XS qw<encode_json decode_json>;

#use Carp qw<carp cluck longmess shortmess>;# qw<carp longmess shortmess>;

use Export::These qw<uhm_slurp>;


# Converts partial incomming data into a stream of completed items
my $dummy_cb=sub {};

sub uhm_slurp {
  my %options=@_;
  
  my $upload_dir=$options{upload_dir};
	my $upload_limit=$options{byte_limit}//$UPLOAD_LIMIT;
  my $close_on_complete=$options{close_on_complete}//1; # Default is to close
  my $mem_flag;

  my $fields_to_file=$options{fields_to_file}//[];   #list of field names to store to disk

  if(defined $upload_dir){
    unless(-d $upload_dir  and -r _ ){
      die "Problem with access to upload dir: $upload_dir";
    }
  }
  else {
    # warn about memory only slurping
    Log::OK::WARN and log_warn "No upload dir destination. Content slurping is memory only";
    $mem_flag=1;
  }
  # Test if upload directory exists;



  my %ctx;
  my $inner=sub {
    my $next=shift;
    my $last;
    sub {
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
          $_[CB]=$dummy_cb;
          $_[ROUTE][1][ROUTE_OUTER_HEAD]->&*;
          return unless $payload;
        }

        # Restore callback after CONTINUE
        #
        $_[CB]=$cb;

        # Wrap payload if presenting as a normal body
        unless(ref $payload){

          # Reuse the head created of the first (and only) part if it exists
          my $head=@$c?$c->[0][0]:{};
          for($_[IN_HEADER]{HTTP_CONTENT_DISPOSITION()}//()){
            $head->{HTTP_CONTENT_DISPOSITION()}=$_;
            my @f=split ";", $_;
            shift @f;

            @f=map split("=", $_,2), @f;
            for my($k, $v)(@f){
              $v=~s/^"//;
              $v=~s/"$//;
              $k=builtin::trim $k;
              $v=builtin::trim $v;
              $head->{"_$k"}=$v;
            }

          }
          for($_[IN_HEADER]{HTTP_CONTENT_TYPE()}//()){
            $head->{HTTP_CONTENT_TYPE()}=$_;
          }
          $head->{_filename}//="single_part";
          $payload=[$head, $payload];
        }

          #For each part (or partial part) we need to append to the right section
          #$c=$ctx{$_[REX]};
          $last=@$c-1;
          if(@$c and $payload->[0] == $c->[$last][0]){
            #Header information is the same. Append data
            #
            if($c->[$last][0]{_filename} and !$mem_flag){
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
            #
            IO::FD::close $c->[$last][1] if @$c and !$mem_flag and $c->[$last][0]{_filename} and $close_on_complete;

            #open new one
            my $h=$payload->[0];

            if($h->{_filename} and !$mem_flag){
              my $path=IO::FD::mktemp catfile $upload_dir, "X" x 10;
              my $error;

              if(defined IO::FD::sysopen(my $fd, $path, O_CREAT|O_RDWR)){
                #store the file descriptor in the body field of the payload     

                if(defined IO::FD::syswrite $fd, $payload->[1]){
                  $payload->[0]{_path}=$path;
                  $payload->[1]=$fd;#$close_on_complete?undef:$fd;
                  push @$c, $payload;
                }
                else {
                  say STDERR "ERROR writing FILE $!";
                  return &rex_error_internal_server_error;
                  #Internal server error
                }
              }
              else {
                #Internal server error
                say STDERR "ERROR OPENING FILE $!";
                return &rex_error_internal_server_error;
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
          if(@$c and !$mem_flag and $c->[$last][0]{_filename} and $close_on_complete){
            IO::FD::close $c->[$last][1];
            $c->[$last][1]=undef;
          }

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

