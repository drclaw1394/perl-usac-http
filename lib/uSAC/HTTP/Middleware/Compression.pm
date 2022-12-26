package uSAC::HTTP::Middleware::Compression;
use strict;
use warnings;

use Exporter 'import';

use feature qw<refaliasing say state>;
no warnings "experimental";

#no feature "indirect";
#use uSAC::HTTP::Session;
use uSAC::HTTP::Code qw<:constants>;
use uSAC::HTTP::Header qw<:constants>;
use uSAC::HTTP::Rex;
use uSAC::HTTP::Constants;

use IO::Compress::Gzip;
use IO::Compress::Gzip::Constants;
use Compress::Raw::Zlib;


use Log::ger;
use Log::OK;





our @EXPORT_OK=qw<
	deflate
	gzip
>;

our @EXPORT=();
our %EXPORT_TAGS=(
	"all"=>[@EXPORT_OK]
);


my @key_indexes=map {$_*2} 0..99;

sub deflate {
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
        if($_[CODE]){
          Log::OK::TRACE and log_debug "Input data length: ".length  $_[4];
          # 0	1 	2   3	    4     5
          # usac, rex, code, headers, data, cb
          \my $buf=\$_[PAYLOAD];
          #Compress::Raw::Zlib::Deflate->new(-AppendOutput=>1, -Level=>6,-ADLER32=>1)
          Log::OK::TRACE and log_debug "Context count: ".scalar keys %out_ctx;
          Log::OK::TRACE and log_debug "Compressor pool: ".scalar @deflate_pool;
          Log::OK::TRACE  and log_trace "doing deflate";

          my $exe;
          my $ctx;
          if($_[HEADER]){
            Log::OK::TRACE and log_debug "Deflate: in header processing";
            \my @headers=$_[HEADER]; #Alias for easy of use and performance
            Log::OK::TRACE and log_trace "deflate: looking for accept";

            ($_[REX]->headers->{ACCEPT_ENCODING}//"") !~ /deflate/iaa and return &$next;
            #Also disable if we are already encoded
            $exe=1;
            my $bypass;
            ($bypass= $_ eq HTTP_CONTENT_ENCODING) and last for @headers[@key_indexes[0.. @headers/2-1]];
            $exe&&=!$bypass;	

            Log::OK::TRACE  and log_trace "exe ". $exe; 
            Log::OK::TRACE  and log_trace "Single shot: ". !$_[CB];

            $ctx=$exe;

            return &$next unless $exe; #bypass is default

            Log::OK::TRACE  and log_trace "No bypass in headers";

            $index=@headers;

            $headers[$_] eq HTTP_CONTENT_LENGTH and ($index=$_, last)
            for @key_indexes[0..@headers/2-1];

            Log::OK::TRACE and log_debug "Content length index: $index";

            splice(@headers, $index, 2, HTTP_CONTENT_ENCODING, "deflate");# if defined $index;
            unless($_[CB]){
              $ctx=pop(@deflate_pool)//Compress::Raw::Zlib::Deflate->new(-AppendOutput=>1, -Level=>6,-ADLER32=>1);

              Log::OK::TRACE and log_trace "single shot";
              my $scratch=""; 	#new scratch each call
              my $status=$ctx->deflate($buf, $scratch);
              $status == Z_OK or log_error "Error creating deflate context";
              $status=$ctx->flush($scratch);
              $ctx->deflateReset;
              Log::OK::TRACE and log_debug "about to push for single shot";
              push @deflate_pool, $ctx;
              #$next->(@_[0,1,2,3], $scratch, @_[5,6]);
              $_[PAYLOAD]=$scratch;
              &$next;
              return;

            }
            else{
              #multiple calls required so setup context
              #my $scratch="";
              $ctx=pop(@deflate_pool)//Compress::Raw::Zlib::Deflate->new(-AppendOutput=>1, -Level=>6,-ADLER32=>1);
              Log::OK::TRACE and log_trace "Multicalls required $_[1]";
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
          $status=$ctx->deflate($buf, $scratch);
          $status == Z_OK or log_error "Error creating deflate context";


          # Push to next stage
          unless($_[CB]){
            Log::OK::TRACE and log_debug "No more data expected";
            #if no callback is provided, then this is the last write
            $status=$ctx->flush($scratch);
            delete $out_ctx{$_[REX]};

            $ctx->deflateReset;
            Log::OK::TRACE and log_debug "about to push for multicall";
            push @deflate_pool, $ctx;
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
              #$next->(@_[0,1,2,3], $scratch,$dummy);# @_[5,6]);
              $_[PAYLOAD]=$scratch;
              $_[CB]=$dummy;
              &$next;
              $_[CB]->($_[6]);	#execute callback to force feed
            }
            else{
              $_[CB]->($_[6]);	#execute callback to force feed
            }
          }
        }
        else{
          delete $out_ctx{$_[REX]};
          &$next;

        }
      },
    )
  };
  [$in, $out];
}

use constant FLAG_APPEND             => 1 ;
use constant FLAG_CRC                => 2 ;
sub gzip{
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
        if($_[CODE]){
          Log::OK::TRACE and log_debug "Input data length: ".length  $_[4];
          # 0	1 	2   3	    4     5
          # usac, rex, code, headers, data, cb
          \my $buf=\$_[4];

          Log::OK::TRACE and log_debug "Context count: ".scalar keys %out_ctx;
          Log::OK::TRACE and log_debug "Compressor pool: ".scalar @deflate_pool;

          Log::OK::TRACE  and log_trace "doing gzip";
          Log::OK::TRACE and log_trace "SIZE OF INCOMING DATA: ". length $_[4];

          my $exe;
          my $ctx;
          if($_[HEADER]){
            Log::OK::TRACE and log_debug "gzipin header processing";
            \my @headers=$_[HEADER]; #Alias for easy of use and performance
            Log::OK::TRACE and log_trace "gzip: looking for accept encoding";

            ($_[REX]->headers->{ACCEPT_ENCODING}//"") !~ /gzip/iaa and return &$next;

            #Also disable if we are already encoded
            $exe=1;
            my $bypass;
            ($bypass = $_ eq HTTP_CONTENT_ENCODING)  and last for @headers[@key_indexes[0.. @headers/2-1]];
            $exe&&=!$bypass;	
            Log::OK::TRACE  and log_trace "exe ". $exe; 
            Log::OK::TRACE  and log_trace "Single shot: ". !$_[CB];

            $ctx=$exe;

            return &$next unless $exe; #bypass is default

            Log::OK::TRACE  and log_trace "No bypass in headers";

            $index=@headers;

            $headers[$_] eq HTTP_CONTENT_LENGTH and ($index=$_, last)
            for @key_indexes[0..@headers/2-1];

            Log::OK::TRACE and log_debug join ", ", @headers;	
            Log::OK::TRACE and log_debug "Content length index: $index";

            splice(@headers, $index, 2, HTTP_CONTENT_ENCODING, "gzip");# if defined $index;
            $ctx=pop(@deflate_pool)//Compress::Raw::Zlib::_deflateInit(FLAG_APPEND|FLAG_CRC,
              Z_BEST_COMPRESSION,
              Z_DEFLATED,
              15+16 , #-MAX_WBITS(),
              MAX_MEM_LEVEL,
              Z_DEFAULT_STRATEGY,
              4096,
              '');

            unless($_[CB]){

              Log::OK::TRACE and log_trace "single shot";
              my $scratch=IO::FD::SV(4096*4);
              #$scratch=IO::Compress::Gzip::Constants::GZIP_MINIMUM_HEADER;
              #my $scratch=IO::Compress::Gzip::Constants::GZIP_MINIMUM_HEADER;
              my $status=$ctx->deflate($buf, $scratch);
              $status == Z_OK or log_error "Error creating deflate context";
              $status=$ctx->flush($scratch);

              #$scratch.=pack("V V", $ctx->crc32(), $ctx->total_in());

              $ctx->deflateReset;
              Log::OK::TRACE and log_debug "about to push for single shot";
              push @deflate_pool, $ctx;
              #$next->(@_[0,1,2,3], $scratch, @_[5,6]);
              $_[PAYLOAD]=$scratch;
              &$next;
              return;

            }
            else{
              #multiple calls required so setup context
              Log::OK::TRACE and log_trace "Multicalls required $_[1]";
              $out_ctx{$_[1]}=$ctx;


            }
          }

          Log::OK::TRACE and log_trace "Processing gzip content";
          # Only process if setup correctly
          #
          Log::OK::TRACE and log_trace $_[1];

          $ctx//=$out_ctx{$_[1]};


          return &$next unless $ctx;


          # Append comppressed data to the scratch when its ready
          #
          my $scratch=""; 	#new scratch each call

          #$scratch=IO::Compress::Gzip::Constants::GZIP_MINIMUM_HEADER if $_[3];

          $status=$ctx->deflate($buf, $scratch);
          $status == Z_OK or log_error "Error creating deflate context";


          # Push to next stage
          unless($_[CB]){
            Log::OK::TRACE and log_debug "No more data expected";
            #if no callback is provided, then this is the last write
            $status=$ctx->flush($scratch);
            #$scratch.=pack("V V", $ctx->crc32(), $ctx->total_in());

            delete $out_ctx{$_[1]};

            $ctx->deflateReset;
            Log::OK::TRACE and log_debug "about to push for multicall";
            push @deflate_pool, $ctx;
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
              #enough data to send out
              #$next->(@_[0,1,2,3], $scratch,$dummy);# @_[5,6]);
              $_[PAYLOAD]=$scratch;
              $_[CB]=$dummy;
              &$next;
              $_[CB]->($_[6]);	#execute callback to force feed
            }
            else {
              $_[CB]->($_[6]);	#execute callback to force feed

            }
          }
        }
        else {
          delete $out_ctx{$_[REX]};
          &$next;

        }
      },
    )
  };
  [$in, $out];
}

1;