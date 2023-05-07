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

use uSAC::HTTP::Constants;# For message strucutre
use uSAC::HTTP::Route;    # For routing structure

our @EXPORT_OK=qw<
		parse_form
		MODE_SERVER
		MODE_CLIENT
		>;
    #make_parser

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
use enum (qw<
  MODE_SERVER
  MODE_CLIENT
>);

use enum (qw<
  STATE_REQUEST
  STATE_RESPONSE 
  STATE_HEADERS 
  STATE_BODY_CONTENT 
  STATE_BODY_CHUNKED 
  STATE_BODY_MULTIPART 
  STATE_ERROR
>);


#make a reader which is bound to a session
sub make_parser{
  # Session, MODE, route_callback;
  # session and alias the variables to lexicals
  # mode is server or  client
  # route_callback is the interace to call to return a route/capture for the url and host
  #
  #my $r=shift;    
  #my $mode=shift; #Client or server
  #my $cb=shift;

  my %options=@_;

  my $r=$options{session};    # 'Session' linking io to middlewares
  my $mode=$options{mode};    # Client or server mode
  my $cb=$options{callback};  # Callback for new rex  processing and route location

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
  my $chunked_state=0;
  my $first=1;
  my $out_header;#={":status"=> -1 };
  my $dummy_cb=sub {};


  sub {
    my $processed=0;

    # Set default HTTP code
    $code=-1;
    try {
      unless(@_){
        Log::OK::TRACE and log_trace "PASSING ON ERROR IN HTTP parser";
        # 0=> site 1=> inner_head 2=> outer_head 3=> error_head/ reset
        #
        $route and $route->[1][ROUTE_ERROR_HEAD]($route, $rex);
        $processed=0;
        return;
      }
      \my $buf=\$_[0];

      #while ( $len=length $buf) {
      while ($buf) {
        #say "_____ Parser : $state";
        #say "____HTTP PARSER_LOOP:". join ", ", @_;
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
          $body_len=undef;
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
              $k=lc $k;

              $val=builtin::trim $val;  #perl 5.36 required
              #$val=~s/\A\s+//;#uo;
              #$val=~s/\s+\z//;#uo;

              \my $e=\$h{$k};
              $e?($e.=",$val"):($e=$val);


              #$ppos=$pos3+2;
              if($k eq "host"){
                $host=$val;
              }
              elsif($k eq "content-length"){
                $body_len= int $val;
              }
              elsif($k eq "connection"){
                $connection=$val;
              }


          }
          $ppos=0;
          $buf=substr($buf, $pos3+4);

        

          $version eq "HTTP/1.0"
          ? ($closeme=($connection!~ /keep-alive/ai))
          : ($closeme=($connection and $connection=~ /close/ai));


          Log::OK::DEBUG and log_debug "Version/method: $method, Close me set to: $closeme";
          Log::OK::DEBUG and log_debug "URI/Code: $uri";
          Log::OK::DEBUG and log_debug "verison/description: $version";

          # Find route
          
          unless($mode){

            $out_header={":status" => -1};
            $h{":method"}=$method;
            $h{":scheme"}="http";
            $h{":authority"}=$host;
            $h{":path"}=$uri;

            # In server mode, the route need needs to be matched for incomming
            # processing and a rex needs to be created
            #
            ($route, $captures)=$cb->($host, "$method $uri");
            $rex=uSAC::HTTP::Rex::new("uSAC::HTTP::Rex", $r, \%h, $host, $version, $method, $uri, $ex, $captures,$out_header);

          }
          else {
            # In client mode the route (and the rex) is already defined.
            # However the headers from incomming request and the response code
            # need updating. 
            #
            #$rex->[uSAC::HTTP::Rex::headers_]=\%h;
            $code=$uri; # NOTE: variable is called $uri, but doubles as code in client mode

            # Set the status in the innerware
            $h{":status"}=$code;

            $out_header=$rex->[uSAC::HTTP::Rex::out_headers_];
          }

          #Before calling the dispatch, setup the parser to process further data.
          #Attempt to further parse the message. It is up to middleware or application
          #to reject the further processing of POST/PUT after the first 'chunk' has been parsed.

          #Push reader. 
          $processed=0; 

          if($body_len){
            # Fixed body length. Single part
              $state=STATE_BODY_CONTENT;
          }
          elsif($h{"transfer-encoding"}//"" =~ /chunked/i){
            # Ignore content length and treat as chunked
              $state=STATE_BODY_CHUNKED;
              $chunked_state=0;
              #next;
          }
          elsif( $h{"content-type"}//"" =~/multipart/i){
            # Treat as multipart
            #
            $body_type = $h{"content-type"};
              $state=STATE_BODY_MULTIPART;
              #next;
          }
          else{
            # no body length specifed assumed no body
            $state=$start_state;
            $payload="";
            $route and $route->[1][ROUTE_INNER_HEAD]($route, $rex, \%h, $out_header, $payload, my $cb=undef);

            #$out_header={":status"=> -1};
          }

          #$state=$start_state;


        }
        elsif($state==STATE_BODY_CONTENT){
          #Process the body until the content length was found or last chunk found.
          #\my $buf=\$_[0];

          #\my %h=$rex->headers;
          #####################################################################################
          # if($out_header){                                                                  #
          #   #                                                                               #
          #   # Single part. Only send the form header once when the out header is set        #
          #   #                                                                               #
          #   $form_headers->{CONTENT_LENGTH}=$body_len;          #copy header to part header #
          #                                                                                   #
          #   $form_headers->{CONTENT_TYPE}=$h{CONTENT_TYPE};                                 #
          # }                                                                                 #
          #####################################################################################

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
            $route and $route->[1][ROUTE_INNER_HEAD]($route, $rex, \%h, $out_header, $payload, my $cb=undef);
            $form_headers={}; #Create new part header
            #$out_header={":status"=> -1};
            $processed=0;
          }
          else {
            # 
            # Not last send
            #
            $route and $route->[1][ROUTE_INNER_HEAD]($route, $rex, \%h, $out_header, $payload, $dummy_cb);
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
                  $route and $route->[1][ROUTE_INNER_HEAD]($route, $rex, \%h, $out_header, [$form_headers, $data], my $cb=undef);
                  #$out_header={":status"=> -1};

                  $buf=substr $buf, $offset+4;
                }
                elsif(substr($buf, $offset, 2) eq CRLF){
                  #not last, regular part
                  my $data=substr($buf, 0, $len);
                  $route and $route->[1][ROUTE_INNER_HEAD]($route, $rex, \%h, $out_header, [$form_headers, $data], $dummy_cb) unless $first;
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
                $route and $route->[1][ROUTE_INNER_HEAD]($route, $rex, \%h, $out_header, [$form_headers, $data], $dummy_cb);
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

          
          #my $lengh=
          if($chunked_state == 0){
            #Size line
            my $index = index $buf, CRLF;
            my $index2= index $buf, CRLF, $index+2;

            #TODO Look into actual limitaiton of chunk size
            #
            my $val=substr($buf,0, $index);
            my $pad=8-length($val);
            $val="0"x$pad.$val if $pad>0;
            my $size=unpack "I>*", pack "H*", $val;#substr($buf, 0, $index);

            if(($index2-$index)==2){
              #Last one
              $state=$start_state;
              my $payload="";
              $buf=substr $buf, $index2+2;
              $route and $route->[1][ROUTE_INNER_HEAD]($route, $rex, \%h, $out_header, $payload, my $cb=undef);

            }
            elsif($index>=0) {
              # Not the last one 
              $buf=substr $buf, $index+2;
              $chunked_state=$size;
            }
            else {
              #ERROR CRLF NOT FOUND
              #$state=STATE_ERROR;
              last;
            }
          }
          else {
            
            if(length($buf) >= ($chunked_state +2)){
              #$buf=substr $buf, $chunked_state+2;
              my $payload=substr $buf, 0, $chunked_state;
              $buf=substr $buf,  $chunked_state+2;
              $chunked_state=0;
              $route and $route->[1][ROUTE_INNER_HEAD]($route, $rex, \%h, $out_header, $payload, $dummy_cb);
              $out_header=undef;
            }
            else {
              # need more data
              last;
            }
            
          }
          #$state=$start_state;

        }
        elsif($state==STATE_ERROR){
          #say  "______ERROR STATE IN PARSER";
          $body_len=0;
          #$closeme=1;
          #$dropper->();
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
        uSAC::HTTP::Rex::rex_write($route, $rex, my $a=500, my $b={HTTP_CONTENT_LENGTH()=>length $context} ,my $c=$context, my $d=undef);
      }
      else {
        uSAC::HTTP::Rex::rex_write($route, $rex, my $a=500, my $b={HTTP_CONTENT_LENGTH()=>0},my $c="", my $d=undef);
      }
    }




  };
}

my %out_ctx;

# Serializer acts as last outerware. 
sub make_serialize{

  my %options=@_;
  my $protocol=$options{protocol}//"HTTP/1.1";
  my $mode=$options{mode}//MODE_SERVER;
  my $code_to_name=$options{information}//\@uSAC::HTTP::Code::code_to_name;

  my $static_headers="";


  #
  # Pre render static headers
  #
  for my ($k, $v)($options{static_headers}->%*){
    $static_headers.="$k: $v".CRLF;
  }

  my $index;
  my $i=1;
  my $ctx;


  sub {
    Log::OK::TRACE and log_trace "Main serialiser called from: ".  join  " ", caller;
    Log::OK::TRACE and log_trace join ", ", @_;

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


    my $reply="";
    if($_[HEADER]){

      # Header with a potential body attached.
      #

      # TODO: fix with multipart uploads? what is the content length
      #
      #TODO: Fix when payload is an array ref. treat as  header, body pairs
      if($_[PAYLOAD] and not exists($_[HEADER]{HTTP_CONTENT_LENGTH()})){

        $ctx=1;
        for($_[HEADER]{HTTP_TRANSFER_ENCODING()}){
          if($_){
            $_=", chunked";
          }
          else{
            $_="chunked";
          }
        }
        $out_ctx{$_[REX]}=$ctx if $_[CB];
      }

      # If no valid code is set then set default 200
      #
      my $code=delete $_[OUT_HEADER]{":status"};
      $code=HTTP_OK if $code<0;

      if($mode == MODE_SERVER){
        # serialize in server mode is a response
        $reply=$protocol." ".$code." ". $code_to_name->[$code]. CRLF;
      }
      else {
        #say "CLIENT CODE: $_[OUT_HEADER]{":status"}";
        # TODO: check CODE. If an error then don't serialize. call the error head
        return &{$_[ROUTE][1][ROUTE_ERROR_HEAD]} unless $code;

        # serialize in client mode is a request
        #$reply="$_[REX][uSAC::HTTP::Rex::method_] $_[REX][uSAC::HTTP::Rex::uri_raw_] $protocol".CRLF;
        $reply="$_[OUT_HEADER]{':method'} $_[OUT_HEADER]{':path'} $protocol".CRLF;
      }

      # Render headers
      #
      foreach my ($k,$v)(%{$_[OUT_HEADER]}){
        $reply.= $k.": ".$v.CRLF  unless index($k, ":" )==0
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
        #$reply.=$_->[1] for($_[PAYLOAD]->@*);
        $reply.=$_[PAYLOAD];
      }

      $_[REX][uSAC::HTTP::Rex::write_]($reply, $cb, $_[6]);
    }
    else{
      # No header specified. Just a body
      #
      if($ctx//=$out_ctx{$_[REX]}){
        $reply= $_[PAYLOAD]?sprintf("%02X".CRLF, length $_[PAYLOAD]).$_[PAYLOAD].CRLF : "";

        #$_[PAYLOAD]= $_[PAYLOAD]?sprintf("%02X".CRLF, length $_[PAYLOAD]).$_[PAYLOAD].CRLF : "";
        unless($_[CB]){
          $reply.="00".CRLF.CRLF;
          delete $out_ctx{$_[REX]};
        }
      }

      $_[REX][uSAC::HTTP::Rex::write_]($reply, $cb)
    }
  }
};


# Dispatch for end of errorware chain. Deletes the context and calls
# reset on the write streamer
sub make_error {

  # Call the error/reset for the rout
  #
  sub {
    if(@_){
      delete $out_ctx{$_[REX]};
      return $_[REX][uSAC::HTTP::Rex::write_]() 
    }
  }
}


1;
