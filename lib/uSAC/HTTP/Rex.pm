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
#use File::Spec::Functions qw<catfile>;
use uSAC::HTTP::Code qw<:constants>;
use uSAC::HTTP::Header qw<:constants>;
use HTTP::State qw<:constants :encode :decode>;
use uSAC::HTTP::Route;

use uSAC::HTTP::Constants;
use IO::FD;
#use Fcntl qw<O_CREAT O_RDWR>;

use Exporter 'import';

use URL::Encode::XS;
use URL::Encode qw<url_decode_utf8>;
use Cpanel::JSON::XS qw<encode_json decode_json>;

our @EXPORT_OK=qw<rex_headers 


usac_multipart_stream


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
rex_error

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
  mw_ctx_
	end_
	>
);

#Add a mechanism for sub classing
use constant KEY_OFFSET=>0;
use constant KEY_COUNT=>end_-version_+1;

require uSAC::HTTP::Middleware;
		
# TODO: rename this subroutine
# This is routine is the glue between server innerware and server outerware
# The innerware is linked to this target at the end.
# Should only be called if you want to jump remaining innerware and go the start
# of outerware
#
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
    #push $_[HEADER]->@*, HTTP_CONNECTION, "close" if($_[REX][closeme_]->$*);
		$_[HEADER]{HTTP_CONNECTION()}="close" if($_[REX][closeme_]->$*);

		#Hack to get HTTP/1.0 With keepalive working
    #push $_[HEADER]->@*, HTTP_CONNECTION, "Keep-Alive" if($_[REX][version_] eq "HTTP/1.0" and !$_[REX][closeme_]->$*);
		$_[HEADER]{HTTP_CONNECTION()}="Keep-Alive" if($_[REX][version_] eq "HTTP/1.0" and !$_[REX][closeme_]->$*);
	}


	#Otherwise this is just a body call
	#
	

	return &{$_[ROUTE][1][2]};	#Execute the outerware for this site/location
  Log::OK::TRACE and log_trace "Rex: End of rex write. after outerware";

}

# Terminates a client innerware
# Client counterpart to rex_write.
# This is used as the 'dispatcher' when linking middleware
#
sub rex_terminate {
  # TODO: implement!
  #Currently does nothing. Just used as an end point
  # Could push a session back to the pool, etc
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
	my $url= $_[ROUTE][1][0]->built_prefix;
	if($_[PAYLOAD]){
		return "$url/$_[PAYLOAD]";
	}
	$url;
	#$_[0][4][0]->built_prefix."/".($_[3]//"");
}

#returns the site object associate with this request
#match, rex, na
sub rex_site {
	$_[ROUTE][1][0];	
}

sub rex_state :lvalue{
	$_[REX][state_];
}

sub rex_peer {
  $_[REX][peer_];
}

#redirect to within site
#match entry
#rex
#partial url
#code
	
#TODO: "Multiple Choice"=>300,

sub rex_redirect_moved{
  if($_[CODE]){
    my $url=$_[PAYLOAD];
    $_[CODE]=HTTP_MOVED_PERMANENTLY;
    #push $_[HEADER]->@*, 
    for my ($k,$v)(HTTP_LOCATION, $url, HTTP_CONTENT_LENGTH, 0){
      $_[HEADER]{$k}=$v;
    }
    $_[PAYLOAD]="";
  }
	&rex_write;
}

sub rex_redirect_see_other{
  if($_[CODE]){
    my $url=$_[PAYLOAD];
    $_[CODE]=HTTP_SEE_OTHER;
    #push $_[HEADER]->@*, 
    for my ($k, $v)(HTTP_LOCATION, $url, HTTP_CONTENT_LENGTH, 0){
      $_[HEADER]{$k}=$v;
    }
    $_[PAYLOAD]="";
  }
	&rex_write;
}

sub rex_redirect_found {
	#my $url=pop;
  if($_[CODE]){
    my $url=$_[PAYLOAD];
    $_[CODE]=HTTP_FOUND;
    #push $_[HEADER]->@*,
    for my ($k, $v)(HTTP_LOCATION, $url, HTTP_CONTENT_LENGTH, 0){
      $_[HEADER]{$k}=$v;
    }
    $_[PAYLOAD]="";
  }
	&rex_write;
	
}

sub rex_redirect_temporary {
  if($_[CODE]){
    my $url=$_[PAYLOAD];
    $_[CODE]=HTTP_TEMPORARY_REDIRECT;
    #push $_[HEADER]->@*
    for my ($k, $v)(HTTP_LOCATION, $url, HTTP_CONTENT_LENGTH, 0){
      $_[HEADER]{$k}=$v;
    }

    $_[PAYLOAD]="";
  }
	&rex_write;
	
}

sub rex_redirect_permanent {
  if($_[CODE]){
    my $url=$_[PAYLOAD];
    $_[CODE]=HTTP_PERMANENT_REDIRECT;
    #push $_[HEADER]->@*,
    for my ($k, $v)(HTTP_LOCATION, $url, HTTP_CONTENT_LENGTH, 0){
      $_[HEADER]{$k}=$v;
    }
    $_[PAYLOAD]="";
  }
	&rex_write;
	
}

sub rex_redirect_not_modified {
  if($_[CODE]){
    my $url=$_[PAYLOAD];
    $_[CODE]=HTTP_NOT_MODIFIED;
    #push $_[HEADER]->@*, 
    for my ($k, $v)(HTTP_LOCATION, $url, HTTP_CONTENT_LENGTH, 0){
      $_[HEADER]{$k}=$v;
    }
    $_[PAYLOAD]="";
  }
	&rex_write;
}

sub rex_redirect_internal;


#General error call, Takes an additional argument of new status code
sub rex_error {
  if($_[CODE]){
    my $site=$_[ROUTE][1][0];
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

  # TODO: 
  # Should the code be force reset to -1 on internal redirect, or leave it to the
  # programmer?
  #
  my $code=$_[CODE];
  my $header=$_[HEADER]?{$_[HEADER]->%*}:{};

  #$_[CODE]=0;
  
  
  $rex->[in_progress_]=1;

	if(($rex->[recursion_count_]) > 10){
		$rex->[recursion_count_]=0;
		#carp "Redirections loop detected for $uri";
		Log::OK::ERROR and log_error("Loop detected. Last attempted url: $uri");	
		rex_write($matcher, $rex, HTTP_LOOP_DETECTED, {HTTP_CONTENT_LENGTH, 0},"",undef);
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
    
    $route->[1][ROUTE_INNER_HEAD]($route, $rex, $code, $header,my $a="",my $b=undef);
  #};
}

sub rex_headers {
	return $_[REX]->[headers_];
}

sub rex_reply_json {
	Log::OK::DEBUG and log_debug "rex_reply_json caller: ". join ", ", caller;

  $_[PAYLOAD]=encode_json $_[PAYLOAD] if(ref($_[PAYLOAD]));

  #push $_[HEADER]->@*,
  for my ($k, $v)(
		HTTP_CONTENT_TYPE, "text/json",
		HTTP_CONTENT_LENGTH, length $_[PAYLOAD]){
    $_[HEADER]{$k}=$v;
  }

	&rex_write;
}

#Assume payload has content
sub rex_reply_html {

#push $_[HEADER]->@*,
  for my ($k, $v)(
		HTTP_CONTENT_TYPE, "text/html",
		HTTP_CONTENT_LENGTH, length $_[PAYLOAD]){
    $_[HEADER]{$k}=$v;
  }

	&rex_write;
}
sub rex_reply_javascript {
#push $_[HEADER]->@*,
  for my ($k, $v)(
		HTTP_CONTENT_TYPE, "text/javascript",
		HTTP_CONTENT_LENGTH, length $_[PAYLOAD]){
    $_[HEADER]{$k}=$v;
  }

	&rex_write;
}

sub rex_reply_text {
#push $_[HEADER]->@*,
  for my ($k, $v)(
		HTTP_CONTENT_TYPE, "text/plain",
		HTTP_CONTENT_LENGTH, length $_[PAYLOAD]){
    $_[HEADER]{$k}=$v;
  }

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
	$_[0][cookies_]//($_[0][cookies_]=decode_cookies $_[0][headers_]{COOKIE});
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
  $self->[mw_ctx_]=[];
  $self->[id_]=$id++;
  #$self->[uri_decoded_]=url_decode_utf8 $self->[uri_raw_];
	$self;
}


#multipart for type.
#Sub parts can be of different types and possible content encodings?
sub usac_multipart_stream {
		my $cb=pop;
		sub {
			my $line=$_[ROUTE];#shift;
			my $rex=$_[REX];#shift;
			#shift;		#remove place holder for mime
			my $session=$rex->[uSAC::HTTP::Rex::session_];
			#check if content type is correct first
			unless (index($rex->[headers_]{CONTENT_TYPE},'multipart/form-data')>=0){
				#$session->[uSAC::HTTP::Session::closeme_]=1;
				$rex->[closeme_]->$*=1;


				rex_write $line, $rex, HTTP_UNSUPPORTED_MEDIA_TYPE,{} ,"multipart/formdata required";
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

# First innerware. Strips site prefix and also monitors if the REX has been marked activly in
# progress
#
sub umw_dead_horse_stripper {
  my ($package, $prefix)=@_;
	my $len=length $prefix;
	my $inner=sub {
		my $inner_next=shift;
    my $index=shift;
    my %options=@_;
		sub {
      return &$inner_next unless $_[CODE];

      Log::OK::TRACE and log_trace "STRIP PREFIX MIDDLEWARE";
      if($_[HEADER]){
        $_[REX][uri_stripped_]= 
        $len
        ?substr($_[REX][uri_raw_], $len)
        : $_[REX][uri_raw_];
      }
      ######################################
      # $_[REX][uri_stripped_]=            #
      # ($_[HEADER] and $len)              #
      #   ?substr($_[REX][uri_raw_], $len) #
      #   : $_[REX][uri_raw_];             #
      ######################################

      &$inner_next; #call the next

      #Check the inprogress flag
      #here we force write unless the rex is in progress

      unless($_[REX][in_progress_]){
        Log::OK::TRACE and log_trace "REX not in progress. forcing rex_write/cb=undef";
        $_[CB]=undef;
        return &rex_write;
      }

      Log::OK::TRACE and log_trace "++++++++++++ END STRIP PREFIX";
      undef;
    },

	};
  my $outer=sub {
    my ($next ,$index, %options)=@_;
    sub {
      say "OUTER DEAD HORSE";
      &$next;
    }
  };

  my $error=sub {
    my ($next ,$index, %options)=@_;
    my $site=$options{site};
    if($site->mode==0){
      sub {
        say "error DEAD HORSE";
        &$next;
      }
    }
    else {
      sub {
        say "CLIENT error dead horse";
        #say $_[ROUTE][1][ROUTE_TABLE][uSAC::HTTP::Site::ACTIVE_COUNT]--;
        #my($route, $captures)=$entry->[uSAC::HTTP::Site::HOST_TABLE_DISPATCH]("$method $uri");


        &$next;
      }
    }
  };

  [$inner, $outer, $error];

}

*rex_parse_form_params=*parse_form_params;


1;
