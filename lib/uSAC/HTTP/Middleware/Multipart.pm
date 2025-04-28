package uSAC::HTTP::Middleware::Multipart;
use v5.36;
use feature "refaliasing";
no warnings "experimental";

use uSAC::HTTP::Constants;
use uSAC::HTTP::Header;
#use Exporter "import";

use Export::These qw<uhm_multipart>;
#our @EXPORT_OK=qw<uhm_multipart>;
#our @EXPORT=@EXPORT_OK;


use constant::more qw<state_=0 first_ buff_ boundary_ b_len_>;
use constant::more qw<BOUNDARY_SEARCH=0 PROCESS_HEADER>;

my $dummy_cb=sub {};

sub uhm_multipart {

  my %in_ctx;

  #Innerware expects serialized payload
  my $inner=sub {
    my $next=shift;
    #my $boundary;
    #my $b_len;
    
    my $form_headers;
    my $processed;
    sub {
      my $ctx;

      if($_[OUT_HEADER]){
        # skip if not multipart
        #
        return &$next unless ($_[IN_HEADER]{HTTP_CONTENT_TYPE()}//"") =~/multipart/i;

        my $boundary="--".(split("=", $_[IN_HEADER]{HTTP_CONTENT_TYPE()}))[1]; #boundary
        $ctx=[
          0,    #state
          1,    #first flag
          "",
          $boundary,
          length($boundary)    #boundary length
        ];
          
        # Only store if expecting more chunks
        $in_ctx{$_[REX]}=$ctx if $_[CB];
      }
      
      # Get the context if not already set
      $ctx//=$in_ctx{$_[REX]};
      # If not set, not multipart;
      return &$next unless $ctx;

      \my $buf=\($ctx->[buff_]);

      $buf.=$_[PAYLOAD];

      #TODO: check for content-disposition and filename if only a single part.
      while(length $buf){
        if($ctx->[state_]==BOUNDARY_SEARCH){
          #TODO: Should this be a search from the back?
          #
          my $index=index($buf, $ctx->[boundary_]);
          if($index>=0){
            # Found full boundary.  end of part
            my $len=($index-2);

            #test if last
            my $offset=$index+$ctx->[b_len_];

            if(substr($buf, $offset, 4) eq "--".CRLF){
              # Last part
              #
              $ctx->[first_]=1;	#reset first.. maybe not needed as destroyed

              # Set next state
              $ctx->[state_]=BOUNDARY_SEARCH;
              my $data=substr($buf, 0, $len);
              
              $_[PAYLOAD]=[$form_headers, $data];
              $_[CB]=undef;
              &$next;

              $buf=substr $buf, $offset+4;
            }
            elsif(substr($buf, $offset, 2) eq CRLF){
              #not last, regular part
              my $data=substr($buf, 0, $len);

              unless($ctx->[first_]){
                # first boundary is start marker....
                $_[PAYLOAD]=[$form_headers, $data];
                $_[CB]=$dummy_cb;
                &$next;
                #$_[OUT_HEADER]=undef;
              }
              $ctx->[first_]=0;
              #move past data and boundary
              $buf=substr $buf, $offset+2;

              # Allocate new part header here as we are about 
              # process headers. Each part has a new hash ref for header
              #
              $form_headers={};
              $ctx->[state_]=PROCESS_HEADER;
              redo;

            }
            else{
              #need more
              #return
            }

          }

          else {
            # Full boundary not found, send partial, upto boundary length
            my $len=length($buf)-$ctx->[b_len_];		#don't send boundary
            my $data=substr($buf, 0, $len);
            $_[PAYLOAD]=[$form_headers, $data];
            $_[CB]=$dummy_cb;
            &$next;
            $buf=substr $buf, $len;
            #wait for next read now
            return;
          }

          #attempt to match extra hyphons
          #next line after boundary is content disposition

        }
        elsif($ctx->[state_]==PROCESS_HEADER){
          #read any headers
          pos($buf)=0;#$processed;

          while (){
            #TODO:  Clean this up

            if( $buf =~ /\G ([^:\000-\037\040]++):[\011\040]*+ ([^\012\015]*+) [\011\040]*+ \015\012/sxogca ){

              my $k=lc $1;
              
              \my $e=\$form_headers->{$k};
              $e = defined $e ? $e.','.$2: $2;

              my $v;
              if($k eq HTTP_CONTENT_DISPOSITION()){
                my @f=split ";", $2;

                #First is expected to always be form-data
                shift @f;
                @f=map split("=", $_,2), @f;
                for my($k, $v)(@f){
                  $v=~s/^"//;
                  $v=~s/"$//;
                  $k=builtin::trim $k;
                  $v=builtin::trim $v;
                  $form_headers->{"_$k"}=$v;
                }
              }
              #need to split to isolate name and filename
              redo;
            }
            elsif ($buf =~ /\G\015\012/sxogca) {
              $processed=pos($buf);

              #readjust the buffer no
              $buf=substr $buf,$processed;
              $processed=0;

              #headers done. setup

              #go back to state 0 and look for boundary
              $ctx->[state_]=BOUNDARY_SEARCH;
              last;
            }
            else {
              die "other multipart header problem";
            }
          }

          #update the offset

        }
        else{
            die "UNKOWN STATE IN MULTIPART MIDDLEWARE";
        }
      }
    }
  };

  #Outerware expects parts
  my $outer=sub {
    my $next=shift;
    sub {
      &$next;
    }
  };

  my $error=sub {
    my $next=shift;
    sub {
      &$next;
    }
  };
  [$inner, $outer, $error];
}
1;
