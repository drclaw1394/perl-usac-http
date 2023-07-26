package uSAC::HTTP::Middleware::Deflate;
use strict;
use warnings;

use feature qw<refaliasing say state>;
no warnings "experimental";

use uSAC::HTTP::Code;
use uSAC::HTTP::Header;
use uSAC::HTTP::Rex;
use uSAC::HTTP::Constants;

use Compress::Raw::Zlib;


use Log::ger;
use Log::OK;





use Export::These qw<uhm_deflate>;




sub uhm_deflate {
  my $in=sub {
    my $next=shift;
    $next;
  };

  state @deflate_pool;
  my %out_ctx; #stores bypass and  compressor
  my $dummy=sub{};
  my $out=sub {
    my $next=shift;
    my $status;
    my $index;
    (sub {
          Log::OK::TRACE and log_debug "Input data length: ".length  $_[PAYLOAD];
          # 0	1 	2   3	    4     5
          # usac, rex, code, headers, data, cb
          #\my $buf=\$_[PAYLOAD];
          #Compress::Raw::Zlib::Deflate->new(-AppendOutput=>1, -Level=>6,-ADLER32=>1)
          Log::OK::TRACE and log_debug "Context count: ".scalar keys %out_ctx;
          Log::OK::TRACE and log_debug "Compressor pool: ".scalar @deflate_pool;
          Log::OK::TRACE  and log_trace "doing deflate";

          my $exe;
          my $ctx;
          if($_[OUT_HEADER]){
            no warnings "uninitialized";
              # Do next unless header is defined and contains gzip
              return &$next if  
              #$_[REX][uSAC::HTTP::Rex::headers_]{ACCEPT_ENCODING} !~ /deflate/
                $_[IN_HEADER]{"accept-encoding"} !~ /deflate/
                or $_[OUT_HEADER]{HTTP_CONTENT_ENCODING()};

            Log::OK::TRACE and log_debug "Deflate: in header processing";
            Log::OK::TRACE and log_trace "deflate: looking for accept";

            $exe=1;

            Log::OK::TRACE  and log_trace "exe ". $exe; 
            Log::OK::TRACE  and log_trace "Single shot: ". !$_[CB];

            $ctx=[];#$exe;

            Log::OK::TRACE  and log_trace "No bypass in headers";


            delete $_[OUT_HEADER]{HTTP_CONTENT_LENGTH()};
            $_[OUT_HEADER]{HTTP_CONTENT_ENCODING()}="deflate";

            unless($_[CB]){
              $ctx->[0]=pop(@deflate_pool)//Compress::Raw::Zlib::Deflate->new(-AppendOutput=>1, -Level=>6,-ADLER32=>1);

              Log::OK::TRACE and log_trace "single shot";
              my $scratch=""; 	#new scratch each call
              my $status=$ctx->[0]->deflate($_[PAYLOAD], $scratch);
              $status == Z_OK or log_error "Error creating deflate context";
              $status=$ctx->[0]->flush($scratch);
              $ctx->[0]->deflateReset;
              Log::OK::TRACE and log_debug "about to push for single shot";
              push @deflate_pool, $ctx->[0];
              #$next->(@_[0,1,2,3], $scratch, @_[5,6]);
              $_[PAYLOAD]=$scratch;
              &$next;
              return;

            }
            else{
              #multiple calls required so setup context
              #my $scratch="";
              $ctx->[0]=pop(@deflate_pool)//Compress::Raw::Zlib::Deflate->new(-AppendOutput=>1, -Level=>6,-ADLER32=>1);
              Log::OK::TRACE and log_trace "Multicalls required $_[REX]";
              $ctx->[1]=$_[CB]; #Save callback
              $out_ctx{$_[REX]}=$ctx;


            }
          }
          Log::OK::TRACE and log_trace "Doing body";
          Log::OK::TRACE and log_trace "Processing deflate content";
          # Only process if setup correctly
          #
          Log::OK::TRACE and log_trace $_[REX];

          $ctx//=$out_ctx{$_[REX]};


          return &$next unless $ctx;


          # Append comppressed data to the scratch when its ready
          #
          my $scratch=""; 	#new scratch each call
          $status=$ctx->[0]->deflate($_[PAYLOAD], $scratch);
          $status == Z_OK or log_error "Error creating deflate context";


          # Push to next stage
          unless($_[CB]){
            Log::OK::TRACE and log_debug "No more data expected";
            #if no callback is provided, then this is the last write
            $status=$ctx->[0]->flush($scratch);
            delete $out_ctx{$_[REX]};

            $ctx->[0]->deflateReset;
            Log::OK::TRACE and log_debug "about to push for multicall";
            push @deflate_pool, $ctx->[0];
            Log::OK::TRACE and log_trace "delete...".scalar keys %out_ctx;

            #$next->(@_[0,1,2,3], $scratch, @_[5,6]);
            $_[PAYLOAD]=$scratch;
            &$next;
            #return;

          }
          else {
            Log::OK::TRACE and log_debug "Expecting more data";
            # more data expected
            if(length $scratch){
              Log::OK::TRACE and log_debug "Writing what we have";
              #enough data to send out
              $_[PAYLOAD]=$scratch;
              $_[CB]=$dummy;
              &$next;
              $ctx->[1]->($_[6]);	#execute callback to force feed
            }
            else{
              $ctx->[1]->($_[6]);	#execute callback to force feed
            }
          }
      },
    )
  };


  my $error=sub {
      my $next=shift;
      sub {
        delete $out_ctx{$_[REX]};
        &$next;
      }
  };

  [$in, $out, $error];
}

1;
