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
#ctx_ reqcount_ 
use enum (
	"start_=0" ,qw< session_
  write_ id_
	closeme_
	dropper_
	server_
	in_progress_

  out_headers_

	recursion_count_
	peer_
	end_
	>
);

#Add a mechanism for sub classing
use constant KEY_OFFSET=>0;
use constant KEY_COUNT=>end_-start_+1;

require uSAC::HTTP::Middleware;
		
# TODO: rename this subroutine
# This is routine is the glue between server innerware and server outerware
# The innerware is linked to this target at the end.
# Should only be called if you want to jump remaining innerware and go the start
# of outerware
#
#Arguments are matcher, rex, in_header, out_header, data, cb
#		0     ,	 1 ,	2,	3,    4,  5
sub rex_write{
  #my $session=$_[1]->[session_];
	if($_[OUT_HEADER]){
		#If headers are supplied, then  process headers
		Log::OK::TRACE and log_trace "REX: Doing rex write====";
		$_[REX][in_progress_]=1;

		#Tell the other end the connection will be closed
    #
    #push $_[HEADER]->@*, HTTP_CONNECTION, "close" if($_[REX][closeme_]->$*);
		$_[OUT_HEADER]{HTTP_CONNECTION()}="close" if($_[REX][closeme_]->$*);

		#Hack to get HTTP/1.0 With keepalive working
		$_[OUT_HEADER]{HTTP_CONNECTION()}="Keep-Alive" if($_[IN_HEADER]{":protocol"} eq "HTTP/1.0" and !$_[REX][closeme_]->$*);
	}


	#Otherwise this is just a body call
	#
	

	return &{$_[ROUTE][1][ROUTE_OUTER_HEAD]};	#Execute the outerware for this site/location
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




##
#OO Methods
#


# Returns the headers parsed at connection time


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
  my $url=$_[PAYLOAD];
  $_[OUT_HEADER]{":status"}=HTTP_MOVED_PERMANENTLY;
  for my ($k,$v)(HTTP_LOCATION, $url, HTTP_CONTENT_LENGTH, 0){
    $_[HEADER]{$k}=$v;
  }
  $_[PAYLOAD]="";
  1;
}

sub rex_redirect_see_other{
  my $url=$_[PAYLOAD];
  $_[OUT_HEADER]{":status"}=HTTP_SEE_OTHER;
  for my ($k, $v)(HTTP_LOCATION, $url, HTTP_CONTENT_LENGTH, 0){
    $_[HEADER]{$k}=$v;
  }
  $_[PAYLOAD]="";
  1;
}

sub rex_redirect_found {
  my $url=$_[PAYLOAD];
  $_[OUT_HEADER]{":status"}=HTTP_FOUND;
  for my ($k, $v)(HTTP_LOCATION, $url, HTTP_CONTENT_LENGTH, 0){
    $_[HEADER]{$k}=$v;
  }
  $_[PAYLOAD]="";
  1;
	
}

sub rex_redirect_temporary {
  my $url=$_[PAYLOAD];
  $_[OUT_HEADER]{":status"}=HTTP_TEMPORARY_REDIRECT;
  for my ($k, $v)(HTTP_LOCATION, $url, HTTP_CONTENT_LENGTH, 0){
    $_[HEADER]{$k}=$v;
  }

  $_[PAYLOAD]="";
  1;
	
}

sub rex_redirect_permanent {
    my $url=$_[PAYLOAD];
    $_[OUT_HEADER]{":status"}=HTTP_PERMANENT_REDIRECT;
    for my ($k, $v)(HTTP_LOCATION, $url, HTTP_CONTENT_LENGTH, 0){
      $_[HEADER]{$k}=$v;
    }
    $_[PAYLOAD]="";
    1;
	
}

sub rex_redirect_not_modified {
  my $url=$_[PAYLOAD];
  $_[OUT_HEADER]{":status"}=HTTP_NOT_MODIFIED;
  for my ($k, $v)(HTTP_LOCATION, $url, HTTP_CONTENT_LENGTH, 0){
    $_[HEADER]{$k}=$v;
  }
  $_[PAYLOAD]="";
  1;
}

sub rex_redirect_internal;


#General error call, Takes an additional argument of new status code
sub rex_error {
  my $site=$_[ROUTE][1][ROUTE_SITE];
  $_[CB]=undef;
  $_[IN_HEADER]{":method"}="GET";
  $_[REX][in_progress_]=1;

  #Locate applicable site urls to handle the error

  for($site->error_uris->{$_[OUT_HEADER]{":status"}}){
    if($_){
      $_[PAYLOAD]=my $a=$_;
      return &rex_redirect_internal
    }
  }
  1;
}


sub rex_error_not_found {
  $_[OUT_HEADER]{":status"}=HTTP_NOT_FOUND;
	&rex_error;
}

sub rex_error_forbidden {
  $_[OUT_HEADER]{":status"}= HTTP_FORBIDDEN;
	&rex_error;
}

sub rex_error_unsupported_media_type {
  $_[OUT_HEADER]{":status"}= HTTP_UNSUPPORTED_MEDIA_TYPE;
	&rex_error;
}

sub rex_error_internal_server_error {
  $_[OUT_HEADER]{":status"}=HTTP_INTERNAL_SERVER_ERROR;
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
  my $in_header=$_[IN_HEADER];
  my $header=$_[OUT_HEADER]?{$_[OUT_HEADER]->%*}:{};

  $rex->[in_progress_]=1;

	if(($rex->[recursion_count_]) > 10){
		$rex->[recursion_count_]=0;
		#carp "Redirections loop detected for $uri";
		Log::OK::ERROR and log_error("Loop detected. Last attempted url: $uri");	
    $_[OUT_HEADER]{":status"}=HTTP_LOOP_DETECTED;
    $_[ROUTE][1][ROUTE_SERIALIZE]->&*;
    #rex_write($matcher, $rex, HTTP_LOOP_DETECTED, {HTTP_CONTENT_LENGTH, 0},"",undef);
		return;
	}

  $rex->[in_progress_]=undef;
  $_[IN_HEADER]{":path"}=$uri;
  $_[IN_HEADER]{":path_stripped"}=$uri;
  #Here we reenter the main processing chain with a  new url, potential
  #undef $_[0];
  $rex->[recursion_count_]++;
  #Log::OK::DEBUG and  log_debug "Redirecting internal to host: $rex->[host_]";
  my $route;
  ($route, $_[IN_HEADER]{":captures"})=$rex->[session_]->server->current_cb->(
    $_[IN_HEADER]{host},
    join(" ", $_[IN_HEADER]{":method"}, $_[IN_HEADER]{":path"}),#New method and url
  );
  
  $route->[1][ROUTE_INNER_HEAD]($route, $rex, $in_header, $header,my $a="",my $b=undef);
}



sub rex_reply_json {
	Log::OK::DEBUG and log_debug "rex_reply_json caller: ". join ", ", caller;
  $_[PAYLOAD]=encode_json $_[PAYLOAD] if(ref($_[PAYLOAD]));
  for my ($k, $v)(
		HTTP_CONTENT_TYPE, "text/json",
		HTTP_CONTENT_LENGTH, length $_[PAYLOAD]){
    $_[HEADER]{$k}=$v;
  }
  1;
}

#Assume payload has content
sub rex_reply_html {
  for my ($k, $v)(
		HTTP_CONTENT_TYPE, "text/html",
		HTTP_CONTENT_LENGTH, length $_[PAYLOAD]){
    $_[HEADER]{$k}=$v;
  }
  1;
}

sub rex_reply_javascript {
  for my ($k, $v)(
		HTTP_CONTENT_TYPE, "text/javascript",
		HTTP_CONTENT_LENGTH, length $_[PAYLOAD]){
    $_[HEADER]{$k}=$v;
  }
  1;
}

sub rex_reply_text {
  for my ($k, $v)(
		HTTP_CONTENT_TYPE, "text/plain",
		HTTP_CONTENT_LENGTH, length $_[PAYLOAD]){
    $_[HEADER]{$k}=$v;
  }
  1;
}


#RW accessor
#Returns the current state information for the rex
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
	#my ($package, $session, $headers, $host, $version, $method, $uri, $ex, $captures, $out_headers)=@_;
	#	    0	        1	          2	      3		    4	        5	      6     7     8           9

	#state $id=0;
	
	Log::OK::DEBUG and log_debug "+++++++Create rex: $id";

	#my $write=undef;

	my $self=bless [], $_[0];
  $self->[session_]=$_[1];


	#NOTE: A single call to Session export. give references to important variables
	
	($self->[closeme_], $self->[dropper_], $self->[server_], undef, undef, $self->[write_], $self->[peer_])= $_[2]->@*;

	$self->[recursion_count_]=0;
  $self->[in_progress_]=undef;
  $self->[id_]=$id++;
	$self;
}


#parse a form in either form-data or urlencoded.
#First arg is rex
#second is data
#third is the header for each part if applicable
sub parse_form_params {
	my $rex=$_[1];
	#parse the fields	
	for ($_[IN_HEADER]{"content-type"}){
		if(/multipart\/form-data/){
			#parse content disposition (name, filename etc)
			my $kv={};
			for(map tr/ //dr, split ";", $_[IN_HEADER]{HTTP_CONTENT_DISPOSITION()}){
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


# First innerware. Strips site prefix and also monitors if the REX has been marked activly in
# progress
#
sub uhm_dead_horse_stripper {
  my ($package, $prefix)=@_;
	my $len=length $prefix;
	my $inner=sub {
		my $inner_next=shift;
    my $index=shift;
    my %options=@_;
		sub {
      Log::OK::TRACE and log_trace "STRIP PREFIX MIDDLEWARE";
      if($_[OUT_HEADER]){
        $_[IN_HEADER]{":path_stripped"}=
        $len
        ?substr($_[IN_HEADER]{":path"}, $len)
        : $_[IN_HEADER]{":path"};

      }
      
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
    $next;
  };

  my $error=sub {
    my ($next ,$index, %options)=@_;
    my $site=$options{site};

    if($site->mode==0){
      sub {
      #say "error DEAD HORSE";
        &$next;
      }
    }
    else {
      sub {
      #say "CLIENT error dead horse";
        #say $_[ROUTE][1][ROUTE_TABLE][uSAC::HTTP::Site::ACTIVE_COUNT]--;
        #my($route, $captures)=$entry->[uSAC::HTTP::Site::HOST_TABLE_DISPATCH]("$method $uri");


        &$next;
      }
    }
  };

  [$inner, $outer, $error];

}



1;
