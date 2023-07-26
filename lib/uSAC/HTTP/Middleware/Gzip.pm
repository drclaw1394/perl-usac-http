package uSAC::HTTP::Middleware::Gzip;
use strict;
use warnings;

use Log::ger;
use Log::OK;


use feature qw<refaliasing say state>;
no warnings "experimental";

#no feature "indirect";
#use uSAC::HTTP::Session;
use uSAC::HTTP::Code qw<:constants>;
use uSAC::HTTP::Header qw<:constants>;
use uSAC::HTTP::Rex;
use uSAC::HTTP::Constants;

use Compress::Raw::Zlib;


use Export::These qw<uhm_gzip>;


use constant::more FLAG_APPEND             => 1 ;
use constant::more FLAG_CRC                => 2 ;
sub uhm_gzip{
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
    (sub {
          Log::OK::TRACE and log_debug "Input data length: ".length  $_[PAYLOAD];
          # 0	1 	2   3	    4     5
          # usac, rex, code, headers, data, cb

          Log::OK::TRACE and log_debug "Context count: ".scalar keys %out_ctx;
          Log::OK::TRACE and log_debug "Compressor pool: ".scalar @deflate_pool;

          Log::OK::TRACE  and log_trace "doing gzip";
          Log::OK::TRACE and log_trace "SIZE OF INCOMING DATA: ". length $_[PAYLOAD];

          my $exe;
          my $ctx;
          if($_[HEADER]){
            no warnings "uninitialized";
            # Do next unless header is defined and contains gzip
            return &$next if 
            #$_[REX][uSAC::HTTP::Rex::headers_]{ACCEPT_ENCODING} !~ /gzip/
              $_[IN_HEADER]{"accept-encoding"} !~ /gzip/
              or $_[OUT_HEADER]{HTTP_CONTENT_ENCODING()};

            Log::OK::TRACE and log_debug "gzipin header processing";
            \my %headers=$_[OUT_HEADER]; #Alias for easy of use and performance
            Log::OK::TRACE and log_trace "gzip: looking for accept encoding";


            #Also disable if we are already encoded
            $exe=1;

            Log::OK::TRACE  and log_trace "exe ". $exe; 
            Log::OK::TRACE  and log_trace "Single shot: ". !$_[CB];

            #$ctx=$exe;
            $ctx=[];


            Log::OK::TRACE  and log_trace "No bypass in headers";


            delete $_[HEADER]{HTTP_CONTENT_LENGTH()};   # remove content length header
            $_[HEADER]{HTTP_CONTENT_ENCODING()}="gzip"; # add encoding header


            $ctx->[0]=(pop(@deflate_pool)//Compress::Raw::Zlib::_deflateInit(FLAG_APPEND|FLAG_CRC,
              Z_BEST_COMPRESSION,
              Z_DEFLATED,
              15+16 , #-MAX_WBITS(),
              MAX_MEM_LEVEL,
              Z_DEFAULT_STRATEGY,
              4096,
              '')
          );

            unless($_[CB]){

              Log::OK::TRACE and log_trace "single shot";
              my $scratch=IO::FD::SV(4096*4);

              my $status=$ctx->[0]->deflate($_[PAYLOAD], $scratch);
              $status == Z_OK or log_error "Error creating deflate context";
              $status=$ctx->[0]->flush($scratch);


              $ctx->[0]->deflateReset;
              Log::OK::TRACE and log_debug "about to push for single shot";
              push @deflate_pool, $ctx->[0];

              $_[PAYLOAD]=$scratch;
              &$next;
              return;

            }
            else{
              #multiple calls required so setup context
              Log::OK::TRACE and log_trace "Multicalls required $_[REX]";
              $ctx->[1]=$_[CB]; #Save callback
              $out_ctx{$_[REX]}=$ctx;
            }
          }

          Log::OK::TRACE and log_trace "Processing gzip content";
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
            #$scratch.=pack("V V", $ctx->crc32(), $ctx->total_in());

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
            Log::OK::TRACE and log_trace "Expecting more data";
            # more data expected
            if(length $scratch){
              #enough data to send out
              #$next->(@_[0,1,2,3], $scratch,$dummy);# @_[5,6]);
              $_[PAYLOAD]=$scratch;
              $_[CB]=$dummy;
              &$next;
              Log::OK::TRACE and log_trace " sent scratch ...About to callback";
              #$_[CB]->($_[6]);	#execute callback to force feed
              $ctx->[1]->($_[6]);	#execute callback to force feed
            }
            else {
              Log::OK::TRACE and log_trace " no scratch ...About to callback";
              #$_[CB]->($_[6]);	#execute callback to force feed
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
