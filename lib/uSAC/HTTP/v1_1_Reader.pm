package uSAC::HTTP::v1_1_Reader;
use feature qw<fc current_sub refaliasing say state try>;
use strict;
use warnings;
no warnings "experimental";
use EV;
use Log::ger;
use Log::OK;


use uSAC::HTTP::Rex;
use Encode qw<find_encoding decode encode decode_utf8>;
use URL::Encode::XS;
use URL::Encode qw<url_decode_utf8>;

use uSAC::HTTP::Constants;# For message strucutre
use uSAC::HTTP::Route;    # For routing structure

use Export::These qw<
		parse_form
		MODE_RESPONSE
		MODE_REQUEST
    MODE_NONE
		>;
    #make_parser


#make_form_data_reader
##		make_form_urlencoded_reader
#		make_socket_writer

#Package global for decoding utf8. Faster than using decode_utf8 function.
our $UTF_8=find_encoding "utf-8";

our $ENABLE_CHUNKED=1;
our $PSGI_COMPAT=undef;
our $KEEP_ALIVE=1;

#use Time::HiRes qw/gettimeofday/;

use Import::These qw<uSAC::HTTP:: Code Method Header>;

use constant::more MAX_READ_SIZE => 128 * 1024, CRLF2=>CRLF.CRLF;


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
use constant::more  qw<
  MODE_RESPONSE=0
  MODE_REQUEST
  MODE_NONE
  >;

use constant::more <STATE_{REQUEST=0,RESPONSE,HEADERS,BODY_CONTENT,BODY_CHUNKED,BODY_MULTIPART,ERROR}>;

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
  my $start_state = $mode == MODE_REQUEST? STATE_RESPONSE : STATE_REQUEST;

  my $psgi_compat=$options{psgi_compat}//$PSGI_COMPAT;
  my $keep_alive=$options{keep_alive}//$KEEP_ALIVE;
  my $enable_pipeline=$options{enable_pipeline}//0;

  my $ex=$r->exports;

  \my $closeme=$ex->[0];
  my $dropper=$ex->[1];
  \my $self=$ex->[2];
  my $rex_ref;
  if($enable_pipeline){
    # Expecting external middleware to pair up requests and responses with sequencing
    $rex_ref=\undef;
  }
  else{
    # Synchronous request response cycle. Outgoing rex is stored in session
    $rex_ref=$ex->[3];
  }

  #\my $rex=$ex->[3];
  #\my $route=$ex->[7];
  my $route;

  \my $rex=$rex_ref;
  
  #weaken $r;

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

  my $body_len=0;
  my $body_type;
  my $multi_state=0;
  my $chunked_state=0;
  my $first=1;
  my $out_header;#={":status"=> -1 };
  my $dummy_cb=sub {};

  #TODO: this needs to be an argument supplied by the server
  # Currently set from the PSGI middleware

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
          if($pos3>=$ppos){
            ($method, $uri, $version)=split " ", substr($buf, $ppos, $pos3-$ppos), 3;
            #$k=index substr($buf, $ppos, $pos3-$ppos), " ";

            if($uri and $version){
              #$uri=url_decode_utf8 $uri;
              #
              #end of line found
              $state   = STATE_HEADERS;
              %h=();
              #$host=undef;
              #$connection="";

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

              ($val)=split(" ", $val, 1);
              #$val=builtin::trim $val;  #perl 5.36 required
              #$val=~s/\A\s+//;#uo;
              #$val=~s/\s+\z//;#uo;

            
              \my $e=\$h{$k};
              if(!defined $e){
                $e=$val;
              }
              elsif(ref $e){
                push @$e, $val;
              }
              else{
                $e=[$e, $val];
              }

              ##################################
              # if($k eq "host"){              #
              #   $host=$val;                  #
              # }                              #
              # elsif($k eq "content-length"){ #
              #   $body_len= int $val;         #
              # }                              #
              # elsif($k eq "connection"){     #
              #   $connection=$val;            #
              # }                              #
              ##################################

              # If the package variable for PSGI compatibility is set
              # we make sure our in header more like psgi environment
              #  Upper case headers sent from the client
              #  combine multiple headers into a single comma separated list
              $h{"HTTP_".((uc $k) =~tr/-/_/r)}=ref $e? join ", ", $e->@*:$e if $psgi_compat;
          }
          $host=$h{host};
          $body_len=$h{"content-length"};
          $connection=$h{"connection"};

          $ppos=0;
          $buf=substr($buf, $pos3+4);

        


          if( $version eq "HTTP/1.0"){
            # Explicit keep alive
            $closeme=($connection!~ /keep-alive/ai);
          }
          else{
            # Explicit close
            #$closeme=($connection and $connection=~ /close/ai);
            $closeme=($connection and $connection eq "close");#=~ /close/ai);
          }


          $closeme=(!$keep_alive or $closeme);

          Log::OK::DEBUG and log_debug "Version/method: $method, Close me set to: $closeme";
          Log::OK::DEBUG and log_debug "URI/Code: $uri";
          Log::OK::DEBUG and log_debug "verison/description: $version";

          # Find route
          
          if($mode==MODE_RESPONSE){

            ##$out_header={":status" => -1};
            $out_header={};
            $h{":method"}=$method;
            $h{":scheme"}="http";
            $h{":authority"}=$host;
            #$h{":path"}=$uri;
            
            ## psudeo psudeo headers
            $h{":protocol"}=$version;
            my $_i;
            #################################
            # $h{":query"}=                 #
            #   (($_i=index($uri, "?"))>=0) #
            #     ?substr($uri, $_i+1)      #
            #     :"";                      #
            #################################
            $_i=index $uri, "?"; 
            if($_i>=0){
              $h{":query"}=substr($uri, $_i+1);
              $uri=$h{":path"}=substr($uri, 0, $_i);
            }
            else {
              $h{":path"}=$uri;
            }

            # In server mode, the route need needs to be matched for incomming
            # processing and a rex needs to be created
            #
            ($route, $h{":captures"})=$cb->($host, "$method $uri");
            $rex=uSAC::HTTP::Rex->new($r, $ex, $route);

            # Work around for HTTP/1.0
            if($closeme){
              $out_header->{HTTP_CONNECTION()}="close";
            }
            else{
              $out_header->{HTTP_CONNECTION()}="Keep-Alive" if($version eq "HTTP/1.0");
            }

          }
          elsif($mode == MODE_REQUEST) {
            # In client mode the route (and the rex) is already defined.
            # However the headers from incomming request and the response code
            # need updating. 
            #
            #$rex->[uSAC::HTTP::Rex::headers_]=\%h;
            $code=$uri; # NOTE: variable is called $uri, but doubles as code in client mode

            # Set the status in the innerware
            $h{":status"}=$code;

            # Loopback the output headers to the input side of the chain.
            # 
            #$out_header=$rex->[uSAC::HTTP::Rex::out_headers_];
            unless($enable_pipeline){
              #Session stores the outgoing rex for clients 
              $out_header=$rex->[uSAC::HTTP::Rex::out_headers_];
              $route=$rex->[uSAC::HTTP::Rex::route_];
              $rex=uSAC::HTTP::Rex->new($r, $ex);
              $rex->[uSAC::HTTP::Rex::out_headers_]=$out_header;
              $rex->[uSAC::HTTP::Rex::route_]=$route;
            }
          }
          else {
            #MODE_NONE
            # Lookup route based on default method, host, version and url and execute innerware.
            # In addition to the start_state being set to header, this should support LSP 
            # 
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
          elsif(index($h{"transfer-encoding"}//"", "chunked")>=0){
            # Ignore content length and treat as chunked
              $state=STATE_BODY_CHUNKED;
              $chunked_state=0;
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

          my $new=length($buf)-$processed;	#length of read buffer

          $new=$new>$body_len?$len:$new;		#clamp to content length
          $processed+=$new;			#track how much we have processed

          my $payload=substr $buf, 0, $new, "";

          if($processed==$body_len){
            #
            # Last send
            #
            $state=$start_state;
            $processed=0;
            #$_[PAYLOAD]="";#substr $buf, 0, $new, "";
            $route and $route->[1][ROUTE_INNER_HEAD]($route, $rex, \%h, $out_header, $payload, my $cb=undef);
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
          last;
        }
        else {
          #Error state
        }
      }
    }
    catch($e){
      #If debugging is enabled. dump the stack trace?

      require Error::Show;

      my $context;
      if(ref($e)){
        $context=Error::Show::context(message=>$e, frames=>[reverse $e->trace->frames]);
      }
      else {
        $context=Error::Show::context($e);
      }
      Log::OK::ERROR and log_error  $context;

      if(Log::OK::DEBUG){
        $route and $route->[1][ROUTE_SERIALIZE]($route, $rex, {}, my $b={HTTP_CONTENT_LENGTH()=>length $context, HTTP__STATUS()=>500} ,my $c=$context, my $d=undef);
      }
      else {
        $route and $route->[1][ROUTE_SERIALIZE]($route, $rex, {}, my $b={HTTP_CONTENT_LENGTH()=>0, HTTP__STATUS()=>500}, my $c="", my $d=undef);
      }
    }
  };
}

my %out_ctx;

# Serializer acts as last outerware. 
sub make_serialize{

  my %options=@_;
  my $protocol=$options{protocol}//"HTTP/1.1";
  my $mode=$options{mode}//MODE_RESPONSE;
  my $code_to_name=$options{information}//\@uSAC::HTTP::Code::code_to_name;

  my $static_headers="";
  my $enable_chunked=$options{enable_chunk}//$ENABLE_CHUNKED;


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
  #Log::OK::TRACE and log_trace "Main serialiser called from: ".  join  " ", caller;
    #Log::OK::TRACE and log_trace join ", ", @_;

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
    my $cb=$_[CB]//$_[REX][uSAC::HTTP::Rex::dropper_];

    my $reply="";
    if($_[OUT_HEADER]){

      # If no valid code is set then set default 200
      #
      my $code=(delete $_[OUT_HEADER]{":status"})//HTTP_OK;

      # TODO: fix with multipart uploads? what is the content length
      #
      if($_[PAYLOAD] and not exists($_[OUT_HEADER]{HTTP_CONTENT_LENGTH()}) and $enable_chunked){

        $_[OUT_HEADER]{HTTP_TRANSFER_ENCODING()}||="chunked";

        $ctx=1; #Mark as needing chunked
        $out_ctx{$_[REX]}=$ctx if $_[CB]; #Save only if we have a callback
      }
      elsif(!$_[PAYLOAD] and $code != HTTP_NOT_MODIFIED){

        # No content but client might not have indicated a close. Force a content length of 0
        $_[OUT_HEADER]{HTTP_CONTENT_LENGTH()}=0;
      }

      #$_[OUT_HEADER]{HTTP_CONTENT_LENGTH()}=0 unless($_[PAYLOAD]);


      if($mode == MODE_RESPONSE){
        $reply=$protocol." ".$code." ". $code_to_name->[$code]. CRLF;
      }
      elsif($mode == MODE_REQUEST) {
        return &{$_[ROUTE][1][ROUTE_ERROR_HEAD]} unless $code;

        # serialize in client mode is a request
        #
        $reply="$_[OUT_HEADER]{':method'} $_[OUT_HEADER]{':path'} $protocol".CRLF;
      }
      else {
        # Mode none
        # DO NO RENDER REQUEST/RESPONSE LINE
      }

      # Render headers
      #
      
      # Special handling of set cookie header for multiple values
      my $v=delete $_[OUT_HEADER]{HTTP_SET_COOKIE()};
      unless(ref $v){
        $reply.= HTTP_SET_COOKIE().": ".$v.CRLF if defined $v;
      }
      else{
        $reply.= HTTP_SET_COOKIE().": ".$_.CRLF  for @$v;
      }


      for my ($k, $v)(%{$_[OUT_HEADER]}){
        # Render anything that isn't a 'pseudo header'. and combine multiple
        # header items onto one line
        #
        next if index($k, ":" )==0;

        unless(ref $v){
          $reply.= $k.": ".$v.CRLF;#  unless index($k, ":" )==0
        }
        else{
          $reply.=$k.": ". (join "; ", @$v).CRLF;
        }
      }

      $reply.=HTTP_DATE.": ".$uSAC::HTTP::Session::Date.CRLF;
      $reply.=$static_headers;
      $reply.=CRLF;

      Log::OK::DEBUG and log_debug "->Serialize: headers:";
      Log::OK::DEBUG and log_debug $reply;

      # mark headers as done, if not informational
      #
      $_[OUT_HEADER]=undef if  $code>=HTTP_OK;


      if($ctx){
        # this is only set if we want chunked
        #
        $reply.= $_[PAYLOAD]?sprintf("%02X".CRLF, length $_[PAYLOAD]).$_[PAYLOAD].CRLF : "";
        $reply.="00".CRLF.CRLF unless $_[CB];

      }
      else {
        $reply.=$_[PAYLOAD];
      }

      $_[REX][uSAC::HTTP::Rex::write_]($reply, $cb);
    }
    else{
      # No header specified. Just a body
      #
      if($ctx//=$out_ctx{$_[REX]}){
        $reply= $_[PAYLOAD]?sprintf("%02X".CRLF, length $_[PAYLOAD]).$_[PAYLOAD].CRLF : "";

        unless($_[CB]){
          # Marked as last call
          $reply.="00".CRLF.CRLF;
          delete $out_ctx{$_[REX]};
        }

        $_[REX][uSAC::HTTP::Rex::write_]($reply, $cb);
      }
      else{
        # not chunked, so just write
        $_[REX][uSAC::HTTP::Rex::write_]($_[PAYLOAD], $cb);
      }

    }
  }
};


# Dispatch for end of errorware chain. Deletes the context and calls
# reset on the write streamer
sub make_error {

  # Call the error/reset for the route
  #
  sub {
    if($_[REX]){
      # There might not be rex. ie could be a complete reply and client closes
      # connection which will trigger this 
      delete $out_ctx{$_[REX]};
      # Reset the serialize stack
      #
      my $c=$_[REX][uSAC::HTTP::Rex::write_];
      $c->() if $c;
    }
  }
}

1;
