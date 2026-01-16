package uSAC::HTTP::v1_1_Reader;
use feature qw<fc current_sub refaliasing state try>;
use strict;
use warnings;
no warnings "experimental";
use uSAC::Log;
use Log::OK;

            use uSAC::IO;
            use Data::Dumper;

use uSAC::HTTP::Rex;
use Encode qw<find_encoding decode encode decode_utf8>;
use URL::Encode::XS;
use URL::Encode qw<url_decode_utf8>;

use uSAC::HTTP::Constants;# For message strucutre
use uSAC::HTTP::Route;    # For routing structure

use HTTP::State;
use HTTP::State::Cookie qw<:all>;

use Export::These qw<
		parse_form
		MODE_RESPONSE
		MODE_REQUEST
    MODE_NONE
		>;
    #make_parser


#make_form_data_reader
##		make_form_urlencoded_reader
#		make_socket_writep

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
  MODE_NONE=0
  MODE_RESPONSE
  MODE_REQUEST
  >;

use constant::more <STATE_{REQUEST=0,RESPONSE,HEADERS,BODY_CONTENT,BODY_CHUNKED,BODY_MULTIPART,ERROR}>;

#make a reader which is bound to a session
sub make_parser{
  # Session, MODE, route_callback;
  # session and alias the variables to lexicals
  # mode is server or  client  or other for supported protocols (LSP)
  # route_callback is the interace to call to return a route/capture for the url and host
  #

  my %options=@_;

  my $r=$options{session};    # 'Session' linking io to middlewares
  my $mode=$options{mode}//MODE_RESPONSE;    # Client or server mode (server default);
  my $cb=$options{callback};  # Callback for new rex  processing and route location

  #default is server mode to handle client requests
  my $start_state = 0;#$mode == MODE_REQUEST? STATE_RESPONSE : STATE_REQUEST;

  my $psgi_compat=$options{psgi_compat}//$PSGI_COMPAT;
  my $keep_alive=$options{keep_alive}//$KEEP_ALIVE;
  my $force_first_line=$options{first_line}//"";

  my $ex=$r->exports;

  \my $closeme=$ex->[0];
  \my $self=$ex->[2];

  my $route;

  my $pipeline=$ex->[3];
  

  use Scalar::Util qw<weaken>;
  weaken $r;

  my ($state, $seq) = ($start_state, 0);
  my ($method, $uri, $version, $len, $pos, $req);
  my $line;

  my %h;		#Define the header storage here, once per connection

  #Temp variables
  my $host;
  my $_i;
  my $connection;
  my $tmp;
  my $pos3;
  my $ppos=0;
  my $k;
  my $val;
  my $rest;
  my $code=-1;
  my $payload="";

  my $body_len=0;
  my $body_type;
  my $multi_state=0;
  my $chunked_state=0;
  my $first=1;
  my $out_header;
  my $dummy_cb=sub {};
  my @lines;

  #TODO: this needs to be an argument supplied by the server
  # Currently set from the PSGI middleware

  #use Scalar::Util qw<weaken>;
  #weaken $r;
  sub {
    Log::OK::TRACE and log_trace "--TOp of parser";
    my $processed=0;
    my $rex;#=$pipeline->[$pipeline->@*-1];

    $rex=$pipeline->[0];

    # Set default HTTP code
    $code=-1;
    try {
      \my $buf=\$_[0][0];

      #while ( $len=length $buf) {
      while ($buf) {
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
        #if ($state== STATE_RESPONSE or $state == STATE_REQUEST) {
        if ($state < STATE_HEADERS) {
          # Don't process new request until existing request is done.
          # Rely on reader being pumped at output stage to retrigger
          
          return if $mode == MODE_RESPONSE and $pipeline->@*;
          $pos3=index $buf, CRLF2;#, $ppos;
          # Header is not complete. need more
          return if($pos3<=0);
          
          # Header is received completely
          #
          %h=();
          $body_type=undef;	
          $body_len=undef;
            
          @lines=split "\015\12", substr($buf,0, $pos3);
          
          # If static first line is specified, use.  For LSP support:
          if($mode){
            ($method, $uri, $version)=split " ", shift @lines; #substr $buf, 0, $vi;
          }
          else {
              ($method, $uri, $version)=split " ", $force_first_line;
          }
          

          for my ($k, $val)(map split(": ", $_, 2), @lines){
            $k=lc $k;
            if($k eq "set-cookie"){
              # Set-Cookie could occur multiple times and is not listable.
              # Special case
              push @$_, $val  for $h{$k}; # auto viv?
            }
            else {
              # RFC 6265 Cookie SHOULD NOT occur more than once. So treat as 'listable'
              $_ = defined $_ ? $_.",".$val : $val for $h{$k};
            }
          }

          $buf=substr $buf, $pos3+4;


          if($psgi_compat){

            # If the package variable for PSGI compatibility is set
            # we make sure our in header more like psgi environment
            #  Upper case headers sent from the client
            #  combine multiple headers into a single comma separated list
            for my ($k, $e)(%h){
              $h{"HTTP_".((uc $k) =~tr/-/_/r)}=ref $e? join ", ", $e->@*:$e;

            }
          }

          $host=$h{host};
          $body_len=$h{"content-length"};
          $connection=$h{"connection"};

          if( $version eq "HTTP/1.0"){
            # Explicit keep alive
            $closeme=($connection!~ /keep-alive/ai);
          }
          else{
            # Explicit close
            $closeme=($connection and $connection=~ /close/ai);
          }


          $closeme=(!$keep_alive or $closeme);

          Log::OK::DEBUG and log_debug "Version/method: $method, Close me set to: ". ($closeme?"true":"false");
          Log::OK::DEBUG and log_debug "URI/Code: $uri";
          Log::OK::DEBUG and log_debug "verison/description: $version";

          # Find route
          
          if($mode==MODE_RESPONSE){

            $rex=uSAC::HTTP::Rex->new($r, $ex);#, $route);
            Log::OK::DEBUG and log_debug  "New rex object: $rex";
            push @$pipeline, $rex;
            $out_header={};
            $rex->[URI]=$uri;
            $rex->[METHOD]=$method;

            $rex->[SCHEME]="http";

            $rex->[AUTHORITY]=$host;

            
            $rex->[PROTOCOL]=$version;

            $_i=index $uri, "?"; 
            if($_i>=0){
              $rex->[QUERY]=substr($uri, $_i+1);

              $uri=$rex->[PATH]=substr($uri, 0, $_i);
            }
            else {
              $uri=$rex->[PATH]=$uri;
            }

            # In server mode, the route need needs to be matched for incomming
            # processing and a rex needs to be created
            #
            #($route, $h{":captures"}) = $cb->($host, "$method $uri");
            ($route, $rex->[CAPTURES]) = $cb->($host, "$method $uri");
            #adump $STDERR, \%+;

            # Set the route for this rex
            $rex->[uSAC::HTTP::Rex::route_]=$route;

            # Work around for HTTP/1.0
            if($closeme){
              $out_header->{HTTP_CONNECTION()}="close";
            }
            else{
              $out_header->{HTTP_CONNECTION()}="Keep-Alive" if($version eq "HTTP/1.0");
            }

          }
          elsif($mode == MODE_REQUEST) {
            #$rex=$pipeline->[0];
            $route=$rex->[uSAC::HTTP::Rex::route_];

            # In client mode the route (and the rex) is already defined.
            # However the headers from incomming request and the response code
            # need updating. 
            #
            #$rex->[uSAC::HTTP::Rex::headers_]=\%h;
            $code=$uri; # NOTE: variable is called $uri, but doubles as code in client mode

            # Set the status in the innerware on the existing rex
            $rex->[STATUS]=$code;

            # Loopback the output headers to the input side of the chain.
            # 
            ########################################################
            # unless($enable_pipeline){                            #
            #   #Session stores the outgoing rex for clients       #
            #   $out_header=$rex->[uSAC::HTTP::Rex::out_headers_]; #
            #   $route=$rex->[uSAC::HTTP::Rex::route_];            #
            #                                                      #
            # }                                                    #
            ########################################################
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

          }
          #$state=$start_state;
        }
        elsif($state==STATE_BODY_CONTENT){
          #Process the body until the content length was found or last chunk found.

          my $new=length($buf)-$processed;	#length of read buffer

          Log::OK::TRACE and log_trace ("DOING BODY CONTENT......... $new");
          $new=$new>$body_len?$len:$new;		#clamp to content length
          $processed+=$new;			#track how much we have processed

          my $payload=substr $buf, 0, $new, "";

          if($processed==$body_len){
            Log::OK::TRACE and log_trace ("DOING BODY CONTENT last ......... $new");
            #
            # Last send
            #
            $state=$start_state;
            $processed=0;
            #$_[PAYLOAD]="";#substr $buf, 0, $new, "";
            $route and $route->[1][ROUTE_INNER_HEAD]($route, $rex, \%h, $out_header, $payload, my $cb=undef);
          }
          else {
            Log::OK::TRACE and log_trace ("DOING BODY CONTENT not last ......... $new");
            # 
            # Not last send
            #
            $route and $route->[1][ROUTE_INNER_HEAD]($route, $rex, \%h, $out_header, $payload, $dummy_cb);
            $body_len-=$new;

            #First pass always sets the header to undef for subsequent middleware
            #$out_header=undef;
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

            my $size=hex substr($buf, 0, $index);

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
              #$out_header=undef;
            }
            else {
              # need more data
              last;
            }
            
          }
          #$state=$start_state;

        }
        elsif($state==STATE_ERROR){
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
        $rex->[STATUS]=HTTP_INTERNAL_SERVER_ERROR;
        # my $s=$rex->[uSAC::HTTP::Rex::session_]->get_serializer();
        #$route and $route->[1][ROUTE_SERIALIZE]($route, $rex, {}, my $b={HTTP_CONTENT_LENGTH()=>length $context} ,my $c=$context, my $d=undef);
        my $s =$_[REX][uSAC::HTTP::Rex::serializer_]->&*;
        $s->($route, $rex, {}, my $b={HTTP_CONTENT_LENGTH()=>length $context} ,my $c=$context, my $d=undef);
      }
      else {
        $rex->[STATUS]=HTTP_INTERNAL_SERVER_ERROR;
        #my $s=$rex->[uSAC::HTTP::Rex::session_]->get_serializer();
        my $s =$_[REX][uSAC::HTTP::Rex::serializer_]->&*;
        #$route and $route->[1][ROUTE_SERIALIZE]($route, $rex, {}, my $b={HTTP_CONTENT_LENGTH()=>0}, my $c="", my $d=undef);
        $s->($route, $rex, {}, my $b={HTTP_CONTENT_LENGTH()=>0}, my $c="", my $d=undef);
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

  my $dummy_cb=sub {};

  sub {
        
        ##############################################################
        # my $seq=$_[REX][uSAC::HTTP::Rex::sequence_];               #
        # my $pipeline=$_[REX][uSAC::HTTP::Rex::pipeline_];          #
        #                                                            #
        # if($seq->{$_[REX][uSAC::HTTP::Rex::id_]}){                 #
        #   push $seq->{$_[REX][uSAC::HTTP::Rex::id_]}->@*, \@_;     #
        #                                                            #
        #                                                            #
        #   # Use the first rex as key and call middleware           #
        #   my $rex=$pipeline->[0];                                  #
        #   my $args=shift $seq->{$rex->[uSAC::HTTP::Rex::id_]}->@*; #
        #   @_=@$args;                                               #
        #                                                            #
        #   # If the CB was not set, then that was the end           #
        #   # of the rex so shift it off                             #
        #   unless ($args->[CB]){                                    #
        #     shift @$pipeline;                                      #
        #     delete $seq->{$rex->[uSAC::HTTP::Rex::id_]};           #
        #   }                                                        #
        # }                                                          #
        # else {                                                     #
        #   # short cut.                                             #
        #   shift @$pipeline unless ($_[CB]);                        #
        # }                                                          #
        ##############################################################



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
    my $cb=$_[CB];

    my $reply=[""];
    #Log::OK::ERROR and log_error "IN SERIALIZE";
    if($_[OUT_HEADER]){

      # If no valid code is set then set default 200
      #
      my $code= $_[REX][STATUS]//HTTP_OK;



      if($mode == MODE_RESPONSE){
        $reply->[0]=$protocol." ".$code." ". $code_to_name->[$code]. CRLF;
        # Render headers
        #

        $reply->[0].=$static_headers;

        # TODO: fix with multipart uploads? what is the content length
        #
        if($_[PAYLOAD] and not exists($_[OUT_HEADER]{HTTP_CONTENT_LENGTH()}) and $enable_chunked){

          # force 
          # Only set if
          $_[OUT_HEADER]{HTTP_TRANSFER_ENCODING()}||="chunked";
          $ctx=1; #Mark as needing chunked
          $out_ctx{$_[REX]}=$ctx if $_[CB]; #Save only if we have a callback
        }
        elsif(!$_[PAYLOAD] and $code != HTTP_NOT_MODIFIED){

          # No content but client might not have indicated a close. Force a content length of 0
          $_[OUT_HEADER]{HTTP_CONTENT_LENGTH()}=0;
        }
        
        # Render date header
        $_[OUT_HEADER]{HTTP_DATE()}//=$uSAC::HTTP::Session::Date;
        #$reply->[0].=HTTP_DATE.": ".$uSAC::HTTP::Session::Date.CRLF;

        my $v=delete $_[OUT_HEADER]{HTTP_SET_COOKIE()};

        for my ($k, $v)(%{$_[OUT_HEADER]}){
          $reply->[0].= $k.": ".$v.CRLF;
        }

        for(@$v){
          if(ref){
            $_=encode_set_cookie $_;
          }
          # else assume already encoded
          $reply->[0].= HTTP_SET_COOKIE().": ".$_.CRLF  
        }



      }
      elsif($mode == MODE_REQUEST) {
        return &{$_[ROUTE][1][ROUTE_ERROR_HEAD]} unless $code;

        # serialize in client mode is a request
        #
        $reply->[0]="$_[REX][METHOD] $_[REX][PATH] $protocol".CRLF;

        $reply->[0].=$static_headers;

        for my ($k, $v)(%{$_[OUT_HEADER]}){
          $reply->[0].= $k.": ".$v.CRLF;
        }
      }
      else {
        # Mode none
        # DO NO RENDER REQUEST/RESPONSE LINE
      }


      #$_[OUT_HEADER]{HTTP_CONTENT_LENGTH()}=0 unless($_[PAYLOAD]);

      #RFC 6265 -> duplicate cookies with the same name not permitted in same
      #response
      # Special handling of set cookie header for multiple values


      #for my ($k, $v)(%{$_[OUT_HEADER]}){
      #$reply->[0].= $k.": ".$v.CRLF;
      #}

      #$reply->[0].=$static_headers;
      $reply->[0].=CRLF;

      Log::OK::TRACE and log_trace "->Serialize: headers=|$_[REX]\n$reply->[0]|=";

      # mark headers as done, if not informational
      #
      $_[OUT_HEADER]=undef if  $code>=HTTP_OK;


      if($ctx){
        # this is only set if we want chunked
        #
        $reply->[0].= $_[PAYLOAD]?sprintf("%02X".CRLF, length $_[PAYLOAD]).$_[PAYLOAD].CRLF : "";
        $reply->[0].="00".CRLF.CRLF unless $_[CB];

      }
      else {
        $reply->[0].=$_[PAYLOAD];
      }
      Log::OK::TRACE and log_trace "HEADER AND BODY in serialize for $_[REX] length: ". length($reply->[0]). "callback: $cb";

      #Log::OK::TRACE and log_trace "--- dropper is currently ". $_[REX][uSAC::HTTP::Rex::dropper_];
      $_[REX][uSAC::HTTP::Rex::write_]($reply, $cb//$dummy_cb);
      #$_[REX][uSAC::HTTP::Rex::write_]($reply, $cb//$_[REX][uSAC::HTTP::Rex::dropper_]);

      # If logging is enabled call logging middleware on a seperate chain
    }
    else{
      #Log::OK::DEBUG and log_debug "BODYONLY in serialize. length: ". length $_[PAYLOAD];
      #Log::OK::DEBUG and log_debug "cb is $cb";
      # No header specified. Just a body
      #
      if($ctx//=$out_ctx{$_[REX]}){
        #Log::OK::DEBUG and log_debug "chunked write... ";
        $reply->[0]= $_[PAYLOAD]?sprintf("%02X".CRLF, length $_[PAYLOAD]).$_[PAYLOAD].CRLF : "";

        unless($_[CB]){
          # Marked as last call
          Log::OK::DEBUG and log_debug "chunked write... last calle (CB=undef)";
          $reply->[0].="00".CRLF.CRLF;
          delete $out_ctx{$_[REX]};
        }

        $_[REX][uSAC::HTTP::Rex::write_]($reply, $cb//$dummy_cb);
      }
      else{
        #Log::OK::DEBUG and log_debug "Las Non chunked write" unless $cb;
        #Log::OK::DEBUG and log_debug "normal write $cb";
        # not chunked, so just write
        $_[REX][uSAC::HTTP::Rex::write_]([$_[PAYLOAD]], $cb//$dummy_cb);
      }

    }

    # The rex has been processed, LAST CALL
    unless($cb){
      if($mode == MODE_RESPONSE){
        ## ONLY shift he pipeline when its a respoonse (SERVER MODE)
        my $pipeline=$_[REX][uSAC::HTTP::Rex::pipeline_];
        shift @$pipeline;
        #$_[REX][uSAC::HTTP::Rex::serializer_]=undef;
        #$_[REX]=undef;
      }
      else {
        my $pipeline=$_[REX][uSAC::HTTP::Rex::pipeline_];
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
      Log::OK::DEBUG and log_debug "v1_1 error called--------";
      #
      #There might not be rex. ie could be a complete reply and client closes
      # connection which will trigger this 
      delete $out_ctx{$_[REX]};
      # Reset the serialize stack
      #
      my $c=$_[REX][uSAC::HTTP::Rex::write_];
      #$c->() if $c;
    }
  }
}


#sub protocol_id { "http/1.1" }

sub protocols {
  "http/1.1"=>[\&make_parser, \&make_serialize, \&make_error]
}

1;
