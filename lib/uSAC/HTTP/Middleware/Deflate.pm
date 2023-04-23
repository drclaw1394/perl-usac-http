package uSAC::HTTP::Middleware::Deflate;
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

use Compress::Raw::Zlib;


use Log::ger;
use Log::OK;





our @EXPORT_OK=qw< umw_deflate >;

our @EXPORT=();
our %EXPORT_TAGS=(
	"all"=>[@EXPORT_OK]
);



sub umw_deflate {
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
          Log::OK::TRACE and log_debug "Input data length: ".length  $_[PAYLOAD];
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
            no warnings "uninitialized";
              # Do next unless header is defined and contains gzip
              return &$next unless 
                $_[REX][uSAC::HTTP::Rex::headers_]{ACCEPT_ENCODING} =~ /deflate/;

            Log::OK::TRACE and log_debug "Deflate: in header processing";
            #\my @headers=$_[HEADER]; #Alias for easy of use and performance
            Log::OK::TRACE and log_trace "deflate: looking for accept";

            $exe=1;
            ########################################################################
            # for my ($k,$v)(@headers){                                            #
            #     return &$next if $k eq HTTP_CONTENT_ENCODING; #bypass is default #
            # }                                                                    #
            ########################################################################
            return &$next if exists$_[HEADER]{HTTP_CONTENT_ENCODING()};

            Log::OK::TRACE  and log_trace "exe ". $exe; 
            Log::OK::TRACE  and log_trace "Single shot: ". !$_[CB];

            $ctx=$exe;

            #return &$next unless $exe; #bypass is default

            Log::OK::TRACE  and log_trace "No bypass in headers";

            ######################################################################################
            # $index=@headers;                                                                   #
            #                                                                                    #
            # my $i=0;                                                                           #
            #                                                                                    #
            # for my ($k, $v)(@headers){                                                         #
            #   $index=$i if $k eq HTTP_CONTENT_LENGTH;                                          #
            #   $i+=2;                                                                           #
            # }                                                                                  #
            #                                                                                    #
            # Log::OK::TRACE and log_debug "Content length index: $index";                       #
            # splice(@headers, $index, 2, HTTP_CONTENT_ENCODING, "deflate");# if defined $index; #
            ######################################################################################

            delete $_[HEADER]{HTTP_CONTENT_LENGTH()};
            $_[HEADER]{HTTP_CONTENT_ENCODING()}="deflate";

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
              Log::OK::TRACE and log_trace "Multicalls required $_[REX]";
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

1;
