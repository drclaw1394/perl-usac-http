package uSAC::HTTP::v1_1_Reader;
use feature qw<fc current_sub refaliasing say state try>;
use strict;
use warnings;
no warnings "experimental";
use EV;
use Log::ger;
use Log::OK;

use Error::Show;
use uSAC::HTTP::Rex;
use Exporter 'import';
use Encode qw<find_encoding decode encode decode_utf8>;
use URL::Encode::XS;
use URL::Encode qw<url_decode_utf8>;
use uSAC::HTTP::Constants;
our @EXPORT_OK=qw<
		make_reader
		parse_form
		MODE_SERVER
		MODE_CLIENT
		>;

our @EXPORT=@EXPORT_OK;

#make_form_data_reader
##		make_form_urlencoded_reader
#		make_socket_writer

#Package global for decoding utf8. Faster than using decode_utf8 function.
our $UTF_8=find_encoding "utf-8";


use Time::HiRes qw/gettimeofday/;
use Scalar::Util 'refaddr', 'weaken';

#use uSAC::HTTP::Session;
#use uSAC::HTTP::Rex;
use uSAC::HTTP::Code qw<:constants>;
use uSAC::HTTP::Method qw<:constants>;
use uSAC::HTTP::Header qw<:constants>;
use constant MAX_READ_SIZE => 128 * 1024;
use constant CRLF2=>CRLF.CRLF;


sub parse_form {
	map { (split "=", $_)} split "&", $_[0] =~ tr/ //dr;
}

#read request line
#read headers
#execute callback to perform uri/method/other matching based on headers
#	-could also be an protocol upgrade => push a dedicated reader to the read stack
#	-method could contain data => push a dedicated reader to the read stack
#
#
use enum (qw<MODE_SERVER MODE_CLIENT>);
use enum (qw<STATE_REQUEST STATE_RESPONSE STATE_HEADERS STATE_BODY_CONTENT STATE_BODY_CHUNKED STATE_BODY_MULTIPART STATE_ERROR>);


#make a reader which is bound to a session
sub make_reader{
  # Session, MODE, route_callback;
  # session and alias the variables to lexicals
  # mode is server or  client
  # route_callback is the interace to call to return a route/capture for the url and host
  #
  my $r=shift;
  my $mode=shift; #Client or server
  my $cb=shift;
  #default is server mode to handle client requests
  my $start_state = $mode == MODE_CLIENT? STATE_RESPONSE : STATE_REQUEST;


  my $ex=$r->exports;

  \my $closeme=$ex->[0];
  my $dropper=$ex->[1];
  \my $self=$ex->[2];
  \my $rex=$ex->[3];
  \my $route=$ex->[7];
  weaken $r;

  #my $cb=$self->current_cb;	
  my ($state, $seq) = ($start_state, 0);
  my ($method, $uri, $version, $len, $pos, $req);
  my $line;

  my %h;		#Define the header storage here, once per connection

  #Temp variables
  my $host;
  my $connection;
  my $tmp;
  my $pos3;
  my $ppos=0;
  my $k;
  my $val;
  my $code=-1;
  my $payload="";

    my $captures;
    my $body_len=0;
    my $body_type;
    my $form_headers={};
    my $multi_state=0;
    my $first=1;
    my $out_header=[];
    my $dummy_cb=sub {};


  sub {
  #say "____HTTP _PARSER:". join ", ", @_;
    my $processed=0;

    ##my %h;

    # Set default HTTP code
    $code=-1;
    try {
      unless(@_){
        Log::OK::TRACE and log_trace "PASSING ON ERROR IN HTTP parser";
        $route and $route->[1][1]($route, $rex);#, $code, $out_header, undef, undef);
        $processed=0;
        return;
      }
      \my $buf=\$_[0];

      #while ( $len=length $buf) {
      while ($buf) {
        say "_____ Parser : $state";
        say "____HTTP PARSER_LOOP:". join ", ", @_;
        #Dual mode variables:
        #	server:
        #	$method => method
        #	$url => uri
        #	$version => http version
        #
        #	client:
        #	$method=> http version
        #	$url=> status code
        #	$version => comment
        #
        if ($state == STATE_REQUEST or $state== STATE_RESPONSE) {
          $pos3=index $buf, CRLF, $ppos;
          $body_type=undef;	
          $body_len=0;
          #if($pos3>=0){
          if($pos3>=$ppos){
            #($method, $uri, $version)=split " ", substr($buf, $ppos, $pos3);
            ($method, $uri, $version)=split " ", substr($buf, $ppos, $pos3-$ppos);

            if($uri and $version){
              #$uri=url_decode_utf8 $uri;
              #
              #end of line found
              $state   = STATE_HEADERS;
              %h=();
              $host=undef;
              $connection="";
              #++$seq;

              #$buf=substr $buf, $pos3+2;
              $ppos=$pos3+2;
            }
            else {
              $state= STATE_ERROR; 
            }

            redo;
          }
          else {
            #Exit the loop as we nee more data pushed in
            #
            if( length($buf) >MAX_READ_SIZE){
              #TODO: create a rex a respond with bad request

              $state=STATE_ERROR;
              redo;

            }
            last;
          }
        }

        elsif ($state == STATE_HEADERS) {
          my $pos3=index $buf, CRLF2, $ppos;


          if ($pos3>MAX_READ_SIZE) {
            $state=STATE_ERROR;
            redo;
          }
          elsif($pos3< $ppos){
            #Not enough
            warn "not enough";
            return;
          }
        

          for my ($k, $val)(
            map split(":", $_, 2) ,
              split("\015\012", substr($buf, $ppos, $pos3-$ppos))
            ){
              $k=~tr/-/_/;
              $k=uc $k;

              #$val=builtin::trim $val;  #perl 5.36 required
              $val=~s/\A\s+//;#uo;
              $val=~s/\s+\z//;#uo;

              \my $e=\$h{$k};
              $e?($e.=",$val"):($e=$val);


              #$ppos=$pos3+2;
              if($k eq "HOST"){
                $host=$val;
              }
              elsif($k eq "CONTENT_LENGTH"){
                $body_len= int $val;
              }
              elsif($k eq "CONNECTION"){
                $connection=$val;
              }


          }
          $ppos=0;
          $buf=substr($buf, $pos3+4);

        

          ##################################################################
          # while () {                                                     #
          #   $pos3=index $buf, CRLF, $ppos;                               #
          #   #if($pos3>0){                                                #
          #   if($pos3>$ppos){                                             #
          #     #($k, $val)=split ":", substr($buf, 0, $pos3), 2;          #
          #     ($k, $val)=split ":", substr($buf, $ppos, $pos3-$ppos), 2; #
          #     $k=~tr/-/_/;                                               #
          #     $k=uc $k;                                                  #
          #                                                                #
          #     $val=builtin::trim $val;  #perl 5.36 required              #
          #                                                                #
          #     \my $e=\$h{$k};                                            #
          #     $e?($e.=",$val"):($e=$val);                                #
          #                                                                #
          #                                                                #
          #     $ppos=$pos3+2;                                             #
          #     if($k eq "HOST"){                                          #
          #       $host=$val;                                              #
          #     }                                                          #
          #     elsif($k eq "CONTENT_LENGTH"){                             #
          #       $body_len= int $val;                                     #
          #     }                                                          #
          #     elsif($k eq "CONNECTION"){                                 #
          #       $connection=$val;                                        #
          #     }                                                          #
          #                                                                #
          #     #TODO what about proxied requests with X-Forwarded-for?    #
          #     #Shoult this set the host as well                          #
          #     #                                                          #
          #     #$buf=substr $buf, $pos3+2;                                #
          #                                                                #
          #     #redo;                                                     #
          #   }                                                            #
          #   #elsif($pos3 == 0){                                          #
          #   elsif($pos3 == $ppos){                                       #
          #     $ppos=0;                                                   #
          #     $buf=substr($buf, $pos3+2);                                #
          #     last;                                                      #
          #   }   #empty line.                                             #
          #                                                                #
          #   else{                                                        #
          #     #-1       Need more                                        #
          #     if (length($buf) > MAX_READ_SIZE) {                        #
          #                                                                #
          #       $state=STATE_ERROR;                                      #
          #       redo;                                                    #
          #     }                                                          #
          #     #warn "Need more";                                         #
          #     return;                                                    #
          #   }                                                            #
          # }                                                              #
          #                                                                #
          ##################################################################
          #Done with headers. 



          #$tmp=$h{CONNECTION}//"";
          $version eq "HTTP/1.0"
          ? ($closeme=($connection!~ /keep-alive/ai))
          : ($closeme=($connection and $connection=~ /close/ai));


          Log::OK::DEBUG and log_debug "Version/method: $method, Close me set to: $closeme";
          Log::OK::DEBUG and log_debug "URI/Code: $uri";
          Log::OK::DEBUG and log_debug "verison/description: $version";

          #Find route
          #unless($rex){
          unless($mode){
            ($route, $captures)=$cb->($host, "$method $uri");
            #
            $rex=uSAC::HTTP::Rex::new("uSAC::HTTP::Rex", $r, \%h, $host, $version, $method, $uri, $ex, $captures);
          }
          else {
            $rex->[uSAC::HTTP::Rex::headers_]=\%h;
            $code=$uri;
            # Assume session has rex already defined (ie client side)
          }

          #Before calling the dispatch, setup the parser to process further data.
          #Attempt to further parse the message. It is up to middleware or application
          #to reject the further processing of POST/PUT after the first 'chunk' has been parsed.

          #Push reader. 
          $processed=0; 
          #$body_len = $h{CONTENT_LENGTH}//0; #number of bytes to read, or 0 if undefined
          if($body_len==0){ 
            #No body
            $state=$start_state;
            $payload="";
            $route and $route->[1][1]($route, $rex, $code, $out_header, $payload, my $cb=undef);
            $out_header=[];
          }
          else{
            $body_type = $h{CONTENT_TYPE};
            if($body_type and $body_type =~/multipart/i){
              $state=STATE_BODY_MULTIPART;
              #next;
            }
            elsif($body_len){
              $state=STATE_BODY_CONTENT;
              #next;
            }
            elsif($h{TRANSFER_ENCODING}//"" =~ /chunked/i){
              $state=STATE_BODY_CHUNKED;
              #next;
            }
          }

          #$state=$start_state;


        }
        elsif($state==STATE_BODY_CONTENT){
          #Process the body until the content length was found or last chunk found.
          #\my $buf=\$_[0];

          #\my %h=$rex->headers;
          if($out_header){
            #
            # Single part. Only send the form header once when the out header is set
            #
            $form_headers->{CONTENT_LENGTH}=$body_len;		#copy header to part header

            $form_headers->{CONTENT_TYPE}=$h{CONTENT_TYPE};
          }

          #here we need to process data untill the end of the body,
          #That could mean a chunked transfer, multipart or urlencoded type data
          #
          #FIXED CONTENT LENGTH
          #if content length is available, then we process until the number of bytes
          #are completed. An undef or callback indicates final write.
          #
          #


          my $new=length($buf)-$processed;	#length of read buffer

          $new=$new>$body_len?$len:$new;		#clamp to content length
          $processed+=$new;			#track how much we have processed

          my $payload=substr $buf, 0, $new, "";

          #say STDERR "PROCESSED: $processed, body len: $body_len";
          if($processed==$body_len){
            #
            # Last send
            #
            $state=$start_state;
            $processed=0;
            $_[PAYLOAD]="";#substr $buf, 0, $new, "";
            $route and $route->[1][1]($route, $rex, $code, $out_header, [$form_headers, $payload], my $cb=undef);
            $form_headers={}; #Create new part header
            $out_header=[];   #Create new out header
            $processed=0;
          }
          else {
            # 
            # Not last send
            #
            $route and $route->[1][1]($route, $rex, $code, $out_header, [$form_headers, $payload], $dummy_cb);
            $body_len-=$new;

            #First pass always sets the header to undef for subsequent middleware
            $out_header=undef;
          }

        }

        elsif($state==STATE_BODY_MULTIPART){

          #START MULTIPART
          #################
          #For multipart, the OUT headers are updated on each new part, with the header info
          #is filled with the part informaion.
          #New parts are detected with new header references.
          #The complete end of the request is marked with undef callback


          #TODO: check for content-disposition and filename if only a single part.
          my $boundary="--".(split("=", $body_type))[1];
          my $b_len=length $boundary;
          while(length $buf){

            if($multi_state==0){
              my $index=index($buf, $boundary);
              if($index>=0){


                #send partial data to callback
                my $len=($index-2);



                #test if last
                my $offset=$index+$b_len;

                if(substr($buf, $offset, 4) eq "--".CRLF){
                  #Last part
                  $first=1;	#reset first;
                  $multi_state=0;
                  $state=$start_state;
                  my $data=substr($buf, 0, $len);
                  $route and $route->[1][1]($route, $rex, $code, $out_header, [$form_headers, $data], my $cb=undef);
                  $out_header=[];

                  $buf=substr $buf, $offset+4;
                }
                elsif(substr($buf, $offset, 2) eq CRLF){
                  #not last, regular part
                  my $data=substr($buf, 0, $len);
                  $route and $route->[1][1]($route, $rex, $code, $out_header, [$form_headers, $data], $dummy_cb) unless $first;
                  $first=0;
                  #move past data and boundary
                  $buf=substr $buf, $offset+2;
                  $multi_state=1;
                  $form_headers={};
                  redo;

                }
                else{
                  #need more
                  #return
                }

              }

              else {
                # Full boundary not found, send partial, upto boundary length
                my $len=length($buf)-$b_len;		#don't send boundary
                my $data=substr($buf, 0, $len);
                $route and $route->[1][1]($route, $rex, $code, $out_header, [$form_headers, $data], $dummy_cb);
                $buf=substr $buf, $len;
                #wait for next read now
                return;
              }

              #attempt to match extra hyphons
              #next line after boundary is content disposition

            }
            elsif($multi_state==1){
              #read any headers
              pos($buf)=0;#$processed;

              while (){
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
                  $multi_state=0;
                  last;
                }
                else {

                }
              }

              #update the offset

            }
            else{

            }
            #say "End of while";
          }
          #say "End of form reader";



          #END Multipart
          ######################



          #$state=$start_state;
        }
        elsif($state==STATE_BODY_CHUNKED){
          #CHUNKED
          #If transfer encoding is chunked, then we process as a series of chunks
          #Again, an undef callback indicats a final write
          $state=$start_state;

        }
        elsif($state==STATE_ERROR){
          say  "______ERROR STATE IN PARSER";
          $body_len=0;
          $closeme=1;
          $dropper->();
          last;
        }
        else {
          #Error state
        }
      }
    }
    catch($e){
      #If debugging is enabled. dump the stack trace?

      my $context;
      if(ref($e)){
        $context=Error::Show::context message=>$e, frames=>[reverse $e->trace->frames];
      }
      else {
        $context=Error::Show::context $e;
      }
      Log::OK::ERROR and log_error  $context;

      if(Log::OK::DEBUG){
        uSAC::HTTP::Rex::rex_write($route, $rex, my $a=500, my $b=[HTTP_CONTENT_LENGTH, length $context] ,my $c=$context, my $d=undef);
      }
      else {
        uSAC::HTTP::Rex::rex_write($route, $rex, my $a=500, my $b=[HTTP_CONTENT_LENGTH, 0],my $c="", my $d=undef);
      }
    }




  };
}

#my @index=map {$_*2} 0..99;

sub make_serialize{
  my %options=@_;
  my $protocol=$options{protocol}//"HTTP/1.1";
  my $mode=$options{mode}//MODE_SERVER;
  my $code_to_name=$options{information}//\@uSAC::HTTP::Code::code_to_name;

  my $static_headers="";


  #
  # Pre render static headers
  #
  for my ($k, $v)($options{static_headers}->@*){
    $static_headers.="$k: $v".CRLF;
  }

  my $index;
  my $i=1;
  my $ctx;

  my %out_ctx;

  sub {
    #continue stack reset on error condition. The IO layer resets
    #on a write call with no arguemts;
    unless($_[CODE]){
      delete $out_ctx{$_[REX]};
      return $_[REX][uSAC::HTTP::Rex::write_]() 
    }
    Log::OK::TRACE and log_trace "Main serialiser called from: ".  join  " ", caller;
    Log::OK::TRACE and log_trace join ", ", @_;
    #use Data::Dumper;
    #say Dumper $_[PAYLOAD];
    #use Data::Dumper;
    #Log::OK::TRACE and log_trace Dumper $_[HEADER];

    $ctx=undef;

    # Getting this far in the middleware indicates we really are in progress
    # Force this setting to make sure.
    $_[REX][uSAC::HTTP::Rex::in_progress_]=1;



    # If the callback is undefined, use the dropper to 'end' the session
    # Otherwise use the provided callback.
    # The writer will only execute the callback if it is a 'true' value.
    # If middleware explicitly sets the callback to 0, it effectively causes
    # a synchronous write with now callback. Which is  useful writing out 
    # small amounts of header data before a body.
    #
    #NOTE: experimenting with not using dropper when undefined.
    # For HTTP/1.1 dropper will be called from other locations on error
    # for HTTP/1.0 dropper is called on close anyhow.
    # saves call
    #
    my $cb=$_[CB];#//$_[REX][uSAC::HTTP::Rex::dropper_];


    if($_[HEADER]){
      # Header with a potential body attached.
      #
      \my @headers=$_[HEADER];

      $index=undef;
      for my ($k, $v)(@headers){
        $index=1 and last if($k eq HTTP_CONTENT_LENGTH);
      }

      # Do chunked if we don't find a content length
      # update appropriate headers
      unless($index){
        $ctx=1; 
        $index=undef;
        $i=1;
        for my ($k,$v)(@headers){
          $i+=2;
          $index=$i and last if $k eq HTTP_TRANSFER_ENCODING;
        }

        unless($index){	
          push @headers, HTTP_TRANSFER_ENCODING, "chunked";

        }
        else{
          $headers[$index].=",chunked";

        }

        # save context if multishot
        # no need to save is single shot
        $out_ctx{$_[REX]}=$ctx if $_[CB]; 
      }

      # If no valid code is set then set default 200
      #
      $_[CODE]=HTTP_OK if $_[CODE]<0;


      #my $reply="HTTP/1.1 ".$_[CODE]." ". $uSAC::HTTP::Code::code_to_name[$_[CODE]]. CRLF;

      my $reply="";
      if($mode == MODE_SERVER){
        # serialize in server mode is a response
        $reply=$protocol." ".$_[CODE]." ". $code_to_name->[$_[CODE]]. CRLF;
      }
      else {
        # serialize in client mode is a request
        $reply="$_[REX][uSAC::HTTP::Rex::method_] $_[REX][uSAC::HTTP::Rex::uri_raw_] $protocol".CRLF;
        #$reply=$protocol." ".$_[CODE]." ". $code_to_name->[$_[CODE]]. CRLF;
      }

      # Render headers
      #
      foreach my ($k,$v)(@{$_[HEADER]}){
        $reply.= $k.": ".$v.CRLF 
      }

      $reply.=HTTP_DATE.": ".$uSAC::HTTP::Session::Date.CRLF;
      $reply.=$static_headers;
      $reply.=CRLF;

      Log::OK::DEBUG and log_debug "->Serialize: headers:";
      Log::OK::DEBUG and log_debug $reply;

      # mark headers as done
      #
      $_[HEADER]=undef;	


      if($ctx){
        # this is only set if we want chunked
        #
        $reply.= $_[PAYLOAD]?sprintf("%02X".CRLF, length $_[PAYLOAD]).$_[PAYLOAD].CRLF : "";
        $reply.="00".CRLF.CRLF unless $_[CB];

      }
      else {
        $reply.=$_[PAYLOAD];
      }

      $_[REX][uSAC::HTTP::Rex::write_]($reply, $cb, $_[6]);
    }
    else{
      # No header specified. Just a body
      #
      if($ctx//=$out_ctx{$_[REX]}){

        $_[PAYLOAD]= $_[PAYLOAD]?sprintf("%02X".CRLF, length $_[PAYLOAD]).$_[PAYLOAD].CRLF : "";
        unless($_[CB]){
          $_[PAYLOAD].="00".CRLF.CRLF;
          delete $out_ctx{$_[REX]};
        }
      }

      $_[REX][uSAC::HTTP::Rex::write_]($_[PAYLOAD],$cb,$_[6])
    }
  }
};



1;
