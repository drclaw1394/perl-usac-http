use feature "refaliasing";
no warnings "experimental";
      use feature "say";
use uSAC::HTTP::Constants;
use Exporter "import";


our @EXPORT_OK=qw<uhm_multipart>;
our @EXPORT=@EXPORT_OK;

#use constant CRLF2=>CRLF.CRLF;
#use constant MAX_READ_SIZE => 128 * 1024;

use enum qw<state_ first_ buff_ boundary_ b_len_>;
use enum qw<BOUNDARY_SEARCH PROCESS_HEADER>;
my $dummy_cb=sub {};
sub uhm_multipart {

  my %in_ctx;

  #Innerware expects serialized payload
  my $inner=sub {
    my $next=shift;
    #my $boundary;
    #my $b_len;
    sub {
      my $ctx;
      #\my $buf=\$_[PAYLOAD];
      use Data::Dumper;
      say STDERR "cb in multipart: ". Dumper $_[CB];
      if($_[OUT_HEADER]){

        # skip if not multipart
        return &$next unless ($_[IN_HEADER]{"content-type"}//"") =~/multipart/i;

        my $boundary="--".(split("=", $_[IN_HEADER]{"content-type"}))[1]; #boundary
        $ctx=[
          0,    #state
          1,    #first flag
          "",
          $boundary,
          length($boundary)    #boundary length
        ];
          
        # Only store if expecting more chunks
        $ctx{$_[REX]}=$ctx if $_[CB];
      }
      
      # Get the context if not already set
      $ctx//=$in_ctx[$_[REX]];
      # If not set, not multipart;
      return &$next unless $ctx;

      \my $buf=\($ctx->[buff_]);

      $buf.=$_[PAYLOAD];

      #TODO: check for content-disposition and filename if only a single part.
      while(length $buf){
        if($ctx->[state_]==BOUNDARY_SEARCH){
          #say "boundary search";
          #TODO: Should this be a search from the back?
          #
          my $index=index($buf, $ctx->[boundary_]);
          if($index>=0){
            #say "full boundary";
            # Found full boundary.  end of part
            my $len=($index-2);

            #test if last
            my $offset=$index+$ctx->[b_len_];

            if(substr($buf, $offset, 4) eq "--".CRLF){
              #say "last part";
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
              ##say "not last part";
              #not last, regular part
              my $data=substr($buf, 0, $len);

              #say "buffer before part ", $buf;
              unless($ctx->[first_]){
                # first boundary is start marker....
                $_[PAYLOAD]=[$form_headers, $data];
                $_[CB]=$dummy_cb;
                &$next;
                #$_[OUT_HEADER]=undef;
              }
              $ctx->[first_]=0;
              #move past data and boundary
              #say "buffer after part ", $buf;
              $buf=substr $buf, $offset+2;
              $ctx->[state_]=PROCESS_HEADER;
              $form_headers={};
              redo;

            }
            else{
              #say "need more";
              #need more
              #return
            }

          }

          else {
            #say "no full boundary";
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
            ##say "process header";
            #say "pos buf: ". pos $buf;
            #say $buf;

            if( $buf =~ /\G ([^:\000-\037\040]++):[\011\040]*+ ([^\012\015]*+) [\011\040]*+ \015\012/sxogca ){

              \my $e=\$form_headers->{uc $1=~tr/-/_/r};
              $e = defined $e ? $e.','.$2: $2;

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
        #say "End of while";
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

