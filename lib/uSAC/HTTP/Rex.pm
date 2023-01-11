package uSAC::HTTP::Rex;
use warnings;
use strict;
use version; our $VERSION = version->declare('v0.1');
use feature qw<current_sub say refaliasing state>;
no warnings "experimental";
our $UPLOAD_LIMIT=1000;
our $PART_LIMIT=$UPLOAD_LIMIT;
use Log::ger;

use Log::OK;

#use Try::Catch;
use Carp qw<carp>;
#use File::Basename qw<basename dirname>;
use File::Spec::Functions qw<catfile>;
use uSAC::HTTP::Code qw<:constants>;
use uSAC::HTTP::Header qw<:constants>;
use uSAC::HTTP::v1_1_Reader;
#use uSAC::HTTP::Server;


#use uSAC::HTTP::Session;
#use uSAC::HTTP::Server;
use uSAC::HTTP::Cookie qw<:all>;
use uSAC::HTTP::Constants;
use IO::FD;
use Fcntl qw<O_CREAT O_RDWR>;

use Exporter 'import';

use URL::Encode::XS;
use URL::Encode qw<url_decode_utf8>;
use Cpanel::JSON::XS qw<encode_json decode_json>;

our @EXPORT_OK=qw<rex_headers 

urlencoded_slurp
urlencoded_file
multipart_slurp
multipart_file

usac_data_stream
usac_multipart_stream
usac_urlencoded_stream
usac_form_stream

usac_data_slurp
usac_multipart_slurp
usac_urlencoded_slurp
usac_form_slurp

rex_parse_form_params 
rex_query_params

rex_method
rex_site_url
rex_site
rex_state
rex_peer

rex_redirect_see_other
rex_redirect_found
rex_redirect_temporary
rex_redirect_not_modified

rex_error_not_found
rex_error_forbidden 
rex_error_internal_server_error 
rex_error_unsupported_media_type 

rex_redirect_internal

rex_reply_json
rex_reply_html
rex_reply_javascript
rex_reply_text

rex_captures
rex_write
>;
our @EXPORT=@EXPORT_OK;




use Time::HiRes qw/gettimeofday/;
use Scalar::Util qw(weaken);
#use Encode qw<decode encode decode_utf8>;


#Class attribute keys
#method_ uri_
#ctx_ reqcount_ 
use enum (
	"version_=0" ,qw< session_
  headers_ write_ query_ query_string_ cookies_ host_ method_ uri_stripped_ uri_raw_ state_ captures_ id_
	closeme_
	dropper_
	server_
	in_progress_

	response_code_
	recursion_count_
	peer_
  uri_decoded_
	end_
	>
);

#Add a mechanism for sub classing
use constant KEY_OFFSET=>0;
use constant KEY_COUNT=>end_-version_+1;

require uSAC::HTTP::Middleware;
		
#Main output subroutine
#Arguments are matcher, rex, code, header, data, cb
#		0     ,	 1 ,	2,	3,    4,  5
sub rex_write{
  #my $session=$_[1]->[session_];
	if($_[HEADER]){
		#If headers are supplied, then  process headers
		Log::OK::TRACE and log_trace "REX: Doing rex write====";
		$_[REX][in_progress_]=1;

		#Tell the other end the connection will be closed
    #
		push $_[HEADER]->@*, HTTP_CONNECTION, "close" if($_[REX][closeme_]->$*);

		#Hack to get HTTP/1.0 With keepalive working
		push $_[HEADER]->@*, HTTP_CONNECTION, "Keep-Alive" if($_[REX][version_] eq "HTTP/1.0" and !$_[REX][closeme_]->$*);
	}


	#Otherwise this is just a body call
	#
	

	&{$_[0][1][2]};	#Execute the outerware for this site/location
  Log::OK::TRACE and log_trace "Rex: End of rex write. after outerware";

}



sub rex_method {
  $_[REX][method_];
}

##
#OO Methods
#


# Returns the headers parsed at connection time
sub headers {
	return $_[0]->[headers_];
}
sub method {
	$_[0][method_];
}
sub uri: lvalue{
	$_[0][uri_raw_];
}
sub uri_stripped :lvalue{
	$_[0][uri_stripped_];
}

#Returns parsed query parameters. If they don't exist, they are parse first
sub query_params {
	unless($_[0][query_]){
		#NOTE: This should already be decoded so no double decode
		#$_[1][query_]={};
		for ($_[0][query_string_]){
			#tr/ //d;

                        ##############################################
                        # for my $pair (split "&"){                  #
                        #         my ($key,$value)=split "=", $pair; #
                        #         $_[1][query_]{$key}=$value;        #
                        #                                            #
                        # }                                          #
                        ##############################################
			$_[0][query_]->%*=map ((split /=/a)[0,1], split /&/a);
		}
	}

	$_[0][query_];
}

sub rex_query_params{
	$_[REX]->query_params;	
}

#Builds a url based on the url of the current site/group
#match, rex, partial url
#Append partial url to end if supplied
#otherwise return the site prefix with no ending slash
sub rex_site_url {
	#match_entry->context->site->built_prefix
	#my $url= $_[0][4][0]->built_prefix;
	my $url= $_[0][1][0]->built_prefix;
	if($_[2]//""){
		return "$url/$_[2]";
	}
	$url;
	#$_[0][4][0]->built_prefix."/".($_[3]//"");
}

#returns the site object associate with this request
#match, rex, na
sub rex_site {
	$_[0][1][0];	
}

sub rex_state :lvalue{
	$_[1][state_];
}

sub rex_peer {
  $_[1][peer_];
}

#redirect to within site
#match entry
#rex
#partial url
#code
	
#TODO: "Multiple Choice"=>300,

sub rex_redirect_moved{
  if($_[CODE]){
    my $url=$_[4];
    $_[2]=HTTP_MOVED_PERMANENTLY;
    push $_[3]->@*, HTTP_LOCATION, $url, HTTP_CONTENT_LENGTH, 0;
    $_[4]="";
  }
	&rex_write;
}

sub rex_redirect_see_other{
  if($_[CODE]){
    my $url=$_[PAYLOAD];
    $_[CODE]=HTTP_SEE_OTHER;
    push $_[HEADER]->@*, HTTP_LOCATION, $url, HTTP_CONTENT_LENGTH, 0;
    $_[PAYLOAD]="";
  }
	&rex_write;
}

sub rex_redirect_found {
	#my $url=pop;
  if($_[CODE]){
    my $url=$_[4];
    $_[2]=HTTP_FOUND;
    push $_[3]->@*, HTTP_LOCATION, $url, HTTP_CONTENT_LENGTH, 0;
    $_[4]="";
  }
	&rex_write;
	
}

sub rex_redirect_temporary {
  if($_[CODE]){
    my $url=$_[4];
    $_[2]=HTTP_TEMPORARY_REDIRECT;
    push $_[3]->@*, HTTP_LOCATION, $url, HTTP_CONTENT_LENGTH, 0;

    $_[4]="";
  }
	&rex_write;
	
}

sub rex_redirect_permanent {
  if($_[CODE]){
    my $url=$_[4];
    $_[2]=HTTP_PERMANENT_REDIRECT;
    push $_[3]->@*, HTTP_LOCATION, $url, HTTP_CONTENT_LENGTH, 0;
    $_[4]="";
  }
	&rex_write;
	
}

sub rex_redirect_not_modified {
  if($_[CODE]){
    my $url=$_[4];
    $_[2]=HTTP_NOT_MODIFIED;
    push $_[3]->@*, HTTP_LOCATION, $url, HTTP_CONTENT_LENGTH, 0;
    $_[4]="";
  }
	&rex_write;
}

sub rex_redirect_internal;


#General error call, Takes an additional argument of new status code
sub rex_error {
  if($_[CODE]){
    my $site=$_[0][1][0];
    $_[CB]=undef;
    $_[REX][method_]="GET";
    $_[REX][in_progress_]=1;
    #$_[CODE]//=HTTP_NOT_FOUND;	#New return code is appened at end

    #Locate applicable site urls to handle the error

    for($site->error_uris->{$_[CODE]}){
      if($_){
        $_[PAYLOAD]=my $a=$_;
        return &rex_redirect_internal
      }

    }
    #return rex_redirect_internal @_, $uri if $uri;

    #If one wasn't found, then make an ugly one
    #$_[PAYLOAD]||="Site: ".$site->id.': Error: '.$_[CODE];
    #$_[PAYLOAD]="";
  }
	&rex_write;
}


sub rex_error_not_found {
  if($_[CODE]){
    $_[CODE]=HTTP_NOT_FOUND;
  }
	&rex_error;
}

sub rex_error_forbidden {
  if($_[CODE]){
    $_[CODE]= HTTP_FORBIDDEN;
  }
	&rex_error;
}

sub rex_error_unsupported_media_type {
  if($_[CODE]){
    $_[CODE]= HTTP_UNSUPPORTED_MEDIA_TYPE;
  }
	&rex_error;
}

sub rex_error_internal_server_error {
  if($_[CODE]){
    $_[CODE]=HTTP_INTERNAL_SERVER_ERROR;
  }
    &rex_error;
}


#Rewrites the uri and matches through the dispatcher
#TODO: recursion limit
sub rex_redirect_internal {

	my ($matcher, $rex, undef, undef, $uri)=@_;
	#state $previous_rex=$rex;
	if(substr($uri,0,1) ne "/"){
		$uri="/".$uri;	
	}

  my $code=$_[CODE];
  my $header=[$_[HEADER]->@*];

  #$_[CODE]=0;
  
  
  $rex->[in_progress_]=1;

	if(($rex->[recursion_count_]) > 10){
		$rex->[recursion_count_]=0;
		#carp "Redirections loop detected for $uri";
		Log::OK::ERROR and log_error("Loop detected. Last attempted url: $uri");	
		rex_write($matcher, $rex, HTTP_LOOP_DETECTED, [HTTP_CONTENT_LENGTH, 0],"",undef);
		return;
	}
  my $t; #$t=AE::timer 0,0,sub {
    say $matcher->[1][1];
    $matcher->[1][1]($matcher, $rex); #force a reset of the current chain, starting at innerware
    $rex->[in_progress_]=undef;
    $rex->[uri_raw_]=$uri;
    $rex->[uri_stripped_]=$uri;
    #say "AFTER CALL TO RESET EXISTING CHAIN";
    #Here we reenter the main processing chain with a  new url, potential
    #new headers and status code
    #undef $_[0];
    $t=undef;
    $rex->[recursion_count_]++;
    Log::OK::DEBUG and  log_debug "Redirecting internal to host: $rex->[host_]";
    my $route;
    ($route, $rex->[captures_])=$rex->[session_]->server->current_cb->(
      $rex->[host_],			#Internal redirects are to same host
      join(" ", $rex->@[method_, uri_raw_]),#New method and url
    );
    
    $route->[1][1]($route, $rex, $code, $header,my $a="",my $b=undef);
  #};
}

sub rex_headers {
	return $_[1]->[headers_];
}

sub rex_reply_json {
	Log::OK::DEBUG and log_debug "rex_reply_json caller: ". join ", ", caller;

  $_[PAYLOAD]=encode_json $_[PAYLOAD] if(ref($_[PAYLOAD]));

  push $_[HEADER]->@*,
		HTTP_CONTENT_TYPE, "text/json",
		HTTP_CONTENT_LENGTH, length $_[PAYLOAD];

	&rex_write;
}

#Assume payload has content
sub rex_reply_html {

  push $_[HEADER]->@*,
		HTTP_CONTENT_TYPE, "text/html",
		HTTP_CONTENT_LENGTH, length $_[PAYLOAD];

	&rex_write;
}
sub rex_reply_javascript {
  push $_[HEADER]->@*,
		HTTP_CONTENT_TYPE, "text/javascript",
		HTTP_CONTENT_LENGTH, length $_[PAYLOAD];

	&rex_write;
}

sub rex_reply_text {
  push $_[HEADER]->@*,
		HTTP_CONTENT_TYPE, "text/plain",
		HTTP_CONTENT_LENGTH, length $_[PAYLOAD];

	&rex_write;
}

sub rex_captures {
	$_[REX][captures_]
}


#returns parsed cookies from headers
#Only parses if the internal field is undefined
#otherwise uses pre parsed values
#Read only
sub cookies :lvalue {
	$_[0][cookies_]//($_[0][cookies_]=parse_cookie $_[0][headers_]{COOKIE});
}

#RW accessor
#Returns the current state information for the rex
sub state :lvalue { $_[0][state_] }
sub captures:lvalue { $_[0][captures_] }
sub writer {
	$_[0][write_];

}
sub session {
	$_[0][session_];
}

sub peer {
  $_[0][peer_];
}
	


my $id=0;	#Instead of using state
my $_i;
sub new {
	#my ($package, $session, $headers, $host, $version, $method, $uri, $ex, $captures)=@_;
	#	0	1	  2	    3		4	5	6   7 8

	#state $id=0;
	my $query_string="";
	$query_string=substr($_[6], $_i+1)
		if(($_i=index($_[6], "?"))>=0);
	
	Log::OK::DEBUG and log_debug "+++++++Create rex: $id";
  Log::OK::DEBUG and log_debug "Query string is $query_string";

	#my $write=undef;

	my $self=bless [ $_[4], $_[1], $_[2], undef, undef, $query_string ,undef,$_[3], $_[5], $_[6], $_[6], {}, [], $id++], $_[0];

  Log::OK::DEBUG and log_debug "Query string is $self->[query_string_]";
	#my $write=$_[1]->[uSAC::HTTP::Session::write_];
	#
	#NOTE: A single call to Session export. give references to important variables
	
	($self->[closeme_], $self->[dropper_], $self->[server_], undef, undef, $self->[write_], $self->[peer_])= $_[7]->@*;#$_[1]->exports->@*;
	$self->[recursion_count_]=0;
  $self->[captures_]=$_[8];
  $self->[in_progress_]=undef;
  $self->[uri_decoded_]=url_decode_utf8 $self->[uri_raw_];
	$self;
}


#multipart for type.
#Sub parts can be of different types and possible content encodings?
sub usac_multipart_stream {
		my $cb=pop;
		sub {
			my $line=$_[0];#shift;
			my $rex=$_[1];#shift;
			#shift;		#remove place holder for mime
			my $session=$rex->[uSAC::HTTP::Rex::session_];
			#check if content type is correct first
			unless (index($rex->[headers_]{CONTENT_TYPE},'multipart/form-data')>=0){
				#$session->[uSAC::HTTP::Session::closeme_]=1;
				$rex->[closeme_]->$*=1;


				rex_write $line, $rex, HTTP_UNSUPPORTED_MEDIA_TYPE,[] ,"multipart/formdata required";
				return;
			}
			#uSAC::HTTP::Session::push_reader
			
			$_[CB]=$cb->();
			$session->push_reader(
				#make_form_data_reader @_, $session, $cb->()

				&make_form_data_reader # @_, $session, $cb->()
			);

			Log::OK::INFO and log_info "multipart stream";
			$_[1][in_progress_]=1;

			$session->pump_reader;
			return;
		}
}


#Innerware which aggrigates the streaming url encoded body content
sub urlencoded_slurp {

  my %options=@_;
	my $upload_limit=$options{byte_limit}//$UPLOAD_LIMIT;
   
  my $inner=sub {
    my $next=shift;
    my %ctx;
    sub {
      #This sub is shared across all requests for  a route. 
      if($_[CODE]){
        my $c;
        if($_[HEADER]){
          #test incomming headers are correct
          
          unless($_[REX]->headers->{CONTENT_TYPE} =~ m{application/x-www-form-urlencoded}){
            $_[PAYLOAD]="adsfasdf";
			      return &rex_error_unsupported_media_type 
          }
          #$content_length=$_[REX]->headers->{CONTENT_LENGTH};
          if(defined $upload_limit  and $_[REX]->headers->{CONTENT_LENGTH} > $upload_limit){
            #@err_res=(HTTP_PAYLOAD_TOO_LARGE, [], "limit: $upload_limit");
            $_[CODE]=HTTP_PAYLOAD_TOO_LARGE;
            $_[HEADER]=[];
            $_[PAYLOAD]="Slurp Limit:  $upload_limit";
            return &rex_error;
          }

          #first call
          $_[REX][in_progress_]=1;
          $c=$ctx{$_[REX]}=$_[PAYLOAD];
          $_[PAYLOAD][0]{_byte_count}=0;
        }
        else{
          #subsequent calls
          $c=$ctx{$_[REX]};
          $c->[1].=$_[PAYLOAD][1];
          $c->[0]{_byte_count}+=length $_[PAYLOAD][1];
        }

        #Check total incomming byte count is within limits
        ##only needed for chunks?
        if(defined $upload_limit  and $c->[0]{_byte_count} > $upload_limit){
          $_[CODE]=HTTP_PAYLOAD_TOO_LARGE;
          $_[HEADER]=[];
          $_[PAYLOAD]="Slurp Limit:  $upload_limit";
          return &rex_error;
        }

        #Accumulate until the last
        if(!$_[CB]){
          #Last set
          $_[PAYLOAD]=[delete $ctx{$_[REX]}];
          undef $c;
          &$next;
        }
        
      }
      else {
        delete $ctx{$_[REX]};
        &$next;
      }

    }
  };

  my $outer=sub {
    my $next=shift;
  };

  [$inner, $outer];

}
sub urlencoded_file {

  my %options=@_;
  #my $upload_dir=$options{upload_dir};
  my $upload_dir=$options{upload_dir}; 
	my $upload_limit=$options{byte_limit}//$UPLOAD_LIMIT;

  my $inner=sub {
    my $next=shift;
    my %ctx;
    sub {
      #This sub is shared across all requests for  a route. 
      say STDERR "URL UPLOAD TO FILE";
      if($_[CODE]){
        my $c;
        if($_[HEADER]){
          unless($_[REX]->headers->{CONTENT_TYPE} =~ m{application/x-www-form-urlencoded}){
            $_[PAYLOAD]="";
			      return &rex_error_unsupported_media_type 
          }
          #$content_length=$_[REX]->headers->{CONTENT_LENGTH};
          if(defined $upload_limit  and $_[REX]->headers->{CONTENT_LENGTH} > $upload_limit){
            #@err_res=(HTTP_PAYLOAD_TOO_LARGE, [], "limit: $upload_limit");
            $_[CODE]=HTTP_PAYLOAD_TOO_LARGE;
            $_[HEADER]=[];
            $_[PAYLOAD]="Limit:  $upload_limit";
            return &rex_error;
          }
          say STDERR "URL UPLOAD TO FILE first call";
          #first call. Open file a temp file
          my $path=IO::FD::mktemp catfile $upload_dir, "X"x10;
          say STDERR "URL UPLOAD TO FILE first call: path is $path";
          my $error;

          if(defined IO::FD::sysopen( my $fd, $path, O_CREAT|O_RDWR)){
            #store the file descriptor in the body field of the payload     
            my $bytes;
            if(defined ($bytes=IO::FD::syswrite $fd, $_[PAYLOAD][1])){
              $_[PAYLOAD][0]{_filename}=$path;
              $_[PAYLOAD][0]{_byte_count}=$bytes;
              $_[PAYLOAD][1]=$fd;
            }
            else {
              say STDERR "ERROR writing FILE $!";
              &rex_error_internal_server_error;
              #Internal server error
            }
          }
          else {
              #Internal server error
              say STDERR "ERROR OPENING FILE $!";
              &rex_error_internal_server_error;
          }

          $_[REX][in_progress_]=1;
          $c=$ctx{$_[REX]}=$_[PAYLOAD];
        }
        else{
          #subsequent calls
          $c=$ctx{$_[REX]};
          my $bytes;
          if(defined($bytes=IO::FD::syswrite $c->[1], $_[PAYLOAD][1])){
            $c->[0]{_byte_count}+=$bytes;

          }
          else {
            #internal server error
              &rex_error_internal_server_error;
          }

        }

        #Check file size is within limits
        if(defined $upload_limit  and $c->[0]{_byte_count} > $upload_limit){
          $_[CODE]=HTTP_PAYLOAD_TOO_LARGE;
          $_[HEADER]=[];
          $_[PAYLOAD]="Limit:  $upload_limit";
          return &rex_error;
        }


        #Accumulate until the last
        if(!$_[CB]){
          #Last set
          my $c=$_[PAYLOAD]=[delete $ctx{$_[REX]}];
          if(defined IO::FD::close $c->[0][1]){
            
          }
          else {
            #Internal server error
          }
          $c->[0][1]=undef;
          &$next;
        }
        
      }
      else {
        #At this point the connection should be closed
        my $c=delete $ctx{$_[REX]};
        if($c->[1]){
          #Force close fds
          IO::FD::close $c->[1];
        }
        &$next;
      }

    }
  };

  my $outer=sub {
    my $next=shift;
  };

  [$inner, $outer];

}




sub multipart_slurp {

  my %options=@_;
  #if a upload directory is specified, then we write the parts to file instead of memory
  #
  my $inner=sub {
    my $next=shift;
    my %ctx;
    my $last;
    sub {
      say STDERR " slurp multipart MIDDLEWARE";
      if($_[CODE]){
        my $c=$ctx{$_[REX]};
        unless($c){
          $c=$ctx{$_[REX]}=[$_[PAYLOAD]];
          $_[REX][in_progress_]=1;
        }
        else {
          #For each part (or partial part) we need to append to the right section
          #$c=$ctx{$_[REX]};
          $last=@$c-1;
          if($_[PAYLOAD][0] == $c->[$last][0]){
            #Header information is the same. Append data
            $c->[$last][1].=$_[PAYLOAD][1];
          }
          else {
            #New part
            push @$c, $_[PAYLOAD];
          }
        }

        #Call next only when accumulation is done
        #Pass the list to the next
        unless($_[CB]){
          $_[PAYLOAD]=delete $ctx{$_[REX]};
          &$next;
        }
      }
      else {
        delete $ctx{$_[REX]};
        &$next;
      }
    }
  };

  my $outer=sub {
    my $next=shift;
  };

  [$inner,$outer];
}
sub multipart_file {

  my %options=@_;
  #my $upload_dir=$options{upload_dir};
  my $upload_dir=$options{upload_dir}; 

  my $inner=sub {
    my $next=shift;
    my %ctx;
    my $last;
    sub {
      say STDERR " file multipart MIDDLEWARE";
      if($_[CODE]){
        my $open;
        my $c=$ctx{$_[REX]};
        unless($c){
          #first call
          $c=$ctx{$_[REX]}=[];#$_[PAYLOAD]];
          $_[REX][in_progress_]=1;

        }
          #For each part (or partial part) we need to append to the right section
          #$c=$ctx{$_[REX]};
          $last=@$c-1;
          if(@$c and $_[PAYLOAD][0] == $c->[$last][0]){
            #Header information is the same. Append data
            my $fd=$c->[$last][1];
            if(defined IO::FD::syswrite $fd, $_[PAYLOAD][1]){
              #not used
            }
          }

          else {
            #New part

            #close old one
            IO::FD::close $c->[$last][1] if @$c;

            #open new one
            my $path=IO::FD::mktemp catfile $upload_dir, "X"x10;
            my $error;

            if(defined IO::FD::sysopen( my $fd, $path, O_CREAT|O_RDWR)){
              #store the file descriptor in the body field of the payload     
              if(defined IO::FD::syswrite $fd, $_[PAYLOAD][1]){
                $_[PAYLOAD][0]{_filename}=$path;
                $_[PAYLOAD][1]=$fd;
                push @$c, $_[PAYLOAD];
              }
              else {
                say STDERR "ERROR writing FILE $!";
                &rex_error_internal_server_error;
                #Internal server error
              }
            }
            else {
              #Internal server error
              say STDERR "ERROR OPENING FILE $!";
              &rex_error_internal_server_error;
            }
          }


        #Call next only when accumulation is done
        #Pass the list to the next
        unless($_[CB]){
            #close old one
            IO::FD::close $c->[$last][1] if @$c;
          $_[PAYLOAD]=delete $ctx{$_[REX]};
          &$next;
        }
      }
      else {
        delete $ctx{$_[REX]};
        &$next;
      }
    }
  };

  my $outer=sub {
    my $next=shift;
  };

  [$inner,$outer];
}


#parse a form in either form-data or urlencoded.
#First arg is rex
#second is data
#third is the header for each part if applicable
sub parse_form_params {
	my $rex=$_[1];
	#0=>line
	#1=>rex
	#2=>code
	#3=>out_header
	#4=>payload
	#5=>section header
	#
	#parse the fields	
	for ($rex->[headers_]{CONTENT_TYPE}){
		if(/multipart\/form-data/){
			#parse content disposition (name, filename etc)
			my $kv={};
			for(map tr/ //dr, split ";", $_[CB]->{CONTENT_DISPOSITION}){
				my ($key, $value)=split "=";
				$kv->{$key}=defined($value)?$value=~tr/"//dr : undef;
			}
			return $kv;
		}
		elsif($_ eq 'application/x-www-form-urlencoded'){
			my $kv={};
			for(split "&", url_decode_utf8 $_[PAYLOAD]){
				my ($key,$value)=split "=";
				$kv->{$key}=$value;
			}
			return $kv;
		}

		else{
			return {};
		}

	}
}

#Parse the query
sub parse_query_params_old {
	my $rex=shift;
	#NOTE: This should already be decoded so no double decode
	my $kv={};
	for(map tr/ //dr, split "&", $rex->[query_string_]){
		my ($key,$value)=split "=";
		$kv->{$key}=$value;

	}
	return $kv;
}

#
sub mw_dead_horse_stripper {
  my ($package, $prefix)=@_;
	my $len=length $prefix;
	sub {
		my $inner_next=shift;
		sub {
      return &$inner_next unless $_[CODE];

      Log::OK::TRACE and log_trace "STRIP PREFIX MIDDLEWARE";
      $_[REX][uri_stripped_]= 
      ($_[HEADER] and $len)
        ?substr($_[REX][uri_raw_], $len)
        : $_[REX][uri_raw_];

      &$inner_next; #call the next

      #Check the inprogress flag
      #here we force write unless the rex is in progress

      unless($_[REX][in_progress_]){
        Log::OK::TRACE and log_trace "REX not in progress. forcing rex_write/cb=undef";
        $_[CB]=undef;
        &rex_write;
      }

      Log::OK::TRACE and log_trace "++++++++++++ END STRIP PREFIX";

    },

	}

}

##############################################################################################################################
# sub DESTROY {                                                                                                              #
#         Log::OK::DEBUG and log_debug "+++++++Destroy rex: $_[0][id_],  session $_[0][session_][uSAC::HTTP::Session::id_]"; #
# }                                                                                                                          #
##############################################################################################################################
#binary data.
# might have contetn-encoding apply however ie base64, gzip

#content type text/plain with optional charset spec
#also setup need to decode any Content-Encoding (ie gzip)



	 

*rex_parse_form_params=*parse_form_params;


1;
