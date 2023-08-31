use v5.36;
package uSAC::HTTP::Rex;
our $VERSION = 'v0.1';

use feature qw<current_sub refaliasing state>;
no warnings "experimental";

our $UPLOAD_LIMIT=1000;
our $PART_LIMIT=$UPLOAD_LIMIT;

use Log::ger;
use Log::OK;

use uSAC::HTTP::Code;
use uSAC::HTTP::Header;
use HTTP::State::Cookie qw<:constants :encode :decode>;

use uSAC::HTTP::Route;

use uSAC::HTTP::Constants;
use IO::FD;
#use Fcntl qw<O_CREAT O_RDWR>;


use URL::Encode::XS;
use URL::Encode qw<url_decode_utf8>;
use Cpanel::JSON::XS qw<encode_json decode_json>;

use Export::These qw<
  rex_site_url
  rex_site
  rex_peer

  rex_redirect_see_other
  rex_redirect_found
  rex_redirect_temporary
  rex_redirect_permanent
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

  rex_write
>;



#use Time::HiRes qw/gettimeofday/;
#use Encode qw<decode encode decode_utf8>;


#Class attribute keys
#ctx_ reqcount_ 
use constant::more {
  "session_"=>0,   # The established channel this rex is a part of 
  "write_"=>1,     # Writer for above
  "id_"=>2,        # ID/sequence of the rex object
	"closeme_"=>3,   # Reference to closer in session
	"dropper_"=>4,   # Reference to dropper in session
	"server_"=>5,      # The server object
	"in_progress_"=>6, # Flag indicating this rex is in progress. This is automatically set by serializer
                  # However if middleware prevents synchronous call to serialize, then this needs
                  # manual setting. USe for debugging mainly

  "out_headers_"=>7, # Glue to link out headers to input side of HTTP Client

	"recursion_count_"=>8,   # Sanity check against server loops
	"peer_"=>9,        # The address structure of the other this connection
  "route_"=>10,     #the route associated with this request
};

		
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
    #$_[OUT_HEADER]{HTTP_CONNECTION()}="close" if($_[REX][closeme_]->$*);

		#Hack to get HTTP/1.0 With keepalive working
    #$_[OUT_HEADER]{HTTP_CONNECTION()}="Keep-Alive" if($_[IN_HEADER]{":protocol"} eq "HTTP/1.0" and !$_[REX][closeme_]->$*);
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
	my $url= $_[ROUTE][REX][ROUTE_SITE]->built_prefix;
	if($_[PAYLOAD]){
		return "$url/$_[PAYLOAD]";
	}
	$url;
	#$_[0][4][0]->built_prefix."/".($_[3]//"");
}

#returns the site object associate with this request
#match, rex, na
sub rex_site {
	$_[ROUTE][REX][ROUTE_SITE];	
}


sub rex_peer {
  $_[REX][peer_];
}

	
#TODO: "Multiple Choice"=>300,

=head2 Client (External) Redirect

These client side redirects rotines return a redirect code to the client. The
middleware environment is configured with correct code and header values, AND
immediately rendered back to the client.  As such, the current middleware
chain must NOT continue. This is done be returning immediately after calling
the routines.

If any remainder middleware is required to execute, manually setting the
error code and Location header will need to be performed and these routines
NOT used.

=head3 rex_redirect_moved

  return &rex_redirect_moved;

Uses the current value of $_[PAYLOAD] as a URL target of client to
redirect to. This invokes the serialiser and the current middleware
chain will be halted immediately. Ensure code returns immediately after
calling.

=cut
sub rex_redirect_moved{
  my $url=$_[PAYLOAD];
  $_[OUT_HEADER]{":status"}=HTTP_MOVED_PERMANENTLY;
  for my ($k,$v)(HTTP_LOCATION, $url, HTTP_CONTENT_LENGTH, 0){
    $_[HEADER]{$k}=$v;
  }
  $_[PAYLOAD]="";
  $_[ROUTE][1][ROUTE_SERIALIZE]->&*;
  undef;
}

=head3 rex_redirect_see_other

  return &rex_redirect_see_other;

Uses the current value of $_[PAYLOAD] as a URL target of client to
redirect to. This invokes the serialiser and the current middleware
chain will be halted immediately. Ensure code returns immediately after
calling.

=cut
sub rex_redirect_see_other{
  my $url=$_[PAYLOAD];
  $url=join "/", $_[ROUTE][ROUTE_SITE]->built_prefix, $$url if ref $url;

  # If url is string and relative, relative to server root
  # if ref to stirng and relative, relative to site
  # full url
  $_[OUT_HEADER]{":status"}=HTTP_SEE_OTHER;
  for my ($k, $v)(HTTP_LOCATION, $url, HTTP_CONTENT_LENGTH, 0){
    $_[HEADER]{$k}=$v;
  }
  $_[PAYLOAD]="";
  $_[ROUTE][1][ROUTE_SERIALIZE]->&*;
  undef;
}


=head3 rex_redirect_found

  return &rex_redirect_found;

Uses the current value of $_[PAYLOAD] as a URL target of client to
redirect to. This invokes the serialiser and the current middleware
chain will be halted immediately. Ensure code returns immediately after
calling.

=cut
sub rex_redirect_found {
  my $url=$_[PAYLOAD];
  $url=join "/", $_[ROUTE][ROUTE_SITE]->built_prefix, $$url if ref $url;
  $_[OUT_HEADER]{":status"}=HTTP_FOUND;
  for my ($k, $v)(HTTP_LOCATION, $url, HTTP_CONTENT_LENGTH, 0){
    $_[HEADER]{$k}=$v;
  }
  $_[PAYLOAD]="";
  $_[ROUTE][1][ROUTE_SERIALIZE]->&*;
  undef;
	
}


=head3 rex_redirect_temporary

  return &rex_redirect_temporary;

Uses the current value of $_[PAYLOAD] as a URL target of client to
redirect to. This invokes the serialiser and the current middleware
chain will be halted immediately. Ensure code returns immediately after
calling.

=cut
sub rex_redirect_temporary {
  my $url=$_[PAYLOAD];
  $url=join "/", $_[ROUTE][ROUTE_SITE]->built_prefix, $$url if ref $url;
  $_[OUT_HEADER]{":status"}=HTTP_TEMPORARY_REDIRECT;
  for my ($k, $v)(HTTP_LOCATION, $url, HTTP_CONTENT_LENGTH, 0){
    $_[HEADER]{$k}=$v;
  }

  $_[PAYLOAD]="";
  $_[ROUTE][1][ROUTE_SERIALIZE]->&*;
  undef;
}

=head3 rex_redirect_permanent

  return &rex_redirect_permanent;

Uses the current value of $_[PAYLOAD] as a URL target of client to
redirect to. This invokes the serialiser and the current middleware
chain will be halted immediately. Ensure code returns immediately after
calling.
=cut
sub rex_redirect_permanent {
    my $url=$_[PAYLOAD];
    $url=join "/", $_[ROUTE][1][ROUTE_SITE]->built_prefix, $$url if ref $url;

    $_[OUT_HEADER]{":status"}=HTTP_PERMANENT_REDIRECT;
    for my ($k, $v)(HTTP_LOCATION, $url, HTTP_CONTENT_LENGTH, 0){
      $_[HEADER]{$k}=$v;
    }
    $_[PAYLOAD]="";
    $_[ROUTE][1][ROUTE_SERIALIZE]->&*;
    undef; #ensure this chain stops
}

=head3 rex_redirect_not_modified

  return &rex_redirect_not_modified;

Uses the current value of $_[PAYLOAD] as a URL target of client to
redirect to. This invokes the serialiser and the current middleware
chain will be halted immediately. Ensure code returns immediately after
calling.
=cut
sub rex_redirect_not_modified {
  #my $url=$_[PAYLOAD];
  $_[OUT_HEADER]{":status"}=HTTP_NOT_MODIFIED;
  #################################################################
  # for my ($k, $v)(HTTP_LOCATION, $url, HTTP_CONTENT_LENGTH, 0){ #
  #   $_[HEADER]{$k}=$v;                                          #
  # }                                                             #
  #################################################################
  $_[PAYLOAD]="";
  $_[ROUTE][1][ROUTE_SERIALIZE]->&*;
  undef;
}

sub rex_redirect_internal;


=head3 rex_error

  return &rex_error;

Resolves a middleware chain/route based on the current output status code. If
none is found, a minimal error response is generated.

Otherwise, an internal redirect to the located chain is performed and
execution continued from there

It is important to end the current middlewar chain execution when calling
this.


=cut
#General error call, Takes an additional argument of new status code
sub rex_error {
  my $site=$_[ROUTE][1][ROUTE_SITE];
  $_[CB]=undef;
  $_[IN_HEADER]{":method"}="GET";
  $_[REX][in_progress_]=1;

  #Locate applicable site urls to handle the error

  for($site->error_uris->{$_[OUT_HEADER]{":status"}}//()){
      $_[PAYLOAD]=my $a=$_;
      $_[OUT_HEADER]{":as_error"}=1;
      return &rex_redirect_internal
  }

  # No custom error page so render immediately 
  $_[PAYLOAD]="";
  $_[ROUTE][1][ROUTE_SERIALIZE]->&*;
  undef;

  # Add this for short hand middleware support. If the redirect is the last
  # statement, the return value is undef, which prevents from automatic
  # middleware execution of the current chain.
  #1;#undef;
}

=head3 rex_error_not_found

  return &rex_error_not_found;

Immediately renders a NOT FOUND error 
=cut
sub rex_error_not_found {
  $_[OUT_HEADER]{":status"}=HTTP_NOT_FOUND;
	&rex_error;
}

=head3 rex_error_forbidden

  return &rex_error_forbidden;

Immediately renders a NOT FOUND error 
=cut

sub rex_error_forbidden {
  $_[OUT_HEADER]{":status"}= HTTP_FORBIDDEN;
	&rex_error;
}

=head3 rex_error_unsupported_media_type

  return &rex_error_unsupported_media_type;

Immediately renders a NOT FOUND error 
=cut
sub rex_error_unsupported_media_type {
  $_[OUT_HEADER]{":status"}= HTTP_UNSUPPORTED_MEDIA_TYPE;
	&rex_error;
}

=head3 rex_error_internal_server_error

  return &rex_error_internal_server_error;

Immediately renders a NOT FOUND error 
=cut
sub rex_error_internal_server_error {
  $_[OUT_HEADER]{":status"}=HTTP_INTERNAL_SERVER_ERROR;
  &rex_error;
}


=head3 rex_redirect_internal

  return &rex_redirect_internal

Redirects the current request to another route, specified in the
C<$_[PAYLOAD]> parameter.

It is important the current middleware chain is prevented from continuing
execution by returning immediately after calling this routine.

=cut
#Rewrites the uri and matches through the dispatcher
#TODO: recursion limit
sub rex_redirect_internal {

	my ($matcher, $rex, undef, undef, $uri)=@_;
  
  # If a scalar reference, 
  $uri=join "/", $_[ROUTE][1][ROUTE_SITE]->built_prefix, $$uri if ref $uri;

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
		Log::OK::ERROR and log_error("Loop detected. Last attempted url: $uri");	
    $_[OUT_HEADER]{":status"}=HTTP_LOOP_DETECTED;
    $_[ROUTE][1][ROUTE_SERIALIZE]->&*;
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
  ($route, $_[IN_HEADER]{":captures"})=$rex->[server_]->current_cb->(
    $_[IN_HEADER]{host},
    join(" ", $_[IN_HEADER]{":method"}, $_[IN_HEADER]{":path"}),#New method and url
  );
  
  $route->[1][ROUTE_INNER_HEAD]($route, $rex, $in_header, $header,my $a="",my $b=undef);
  undef;
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
	#my ($package, $session, $exports)
	#	    0	        1	          2	      3		    4	        5	      6     7     8           9

	
	Log::OK::DEBUG and log_debug "+++++++Create rex: $id";


	my $self=bless [], $_[0];

  $self->[session_]=$_[1];
  $self->[route_]=$_[2];

	#NOTE: A single call to Session export. give references to important variables
	
	($self->[closeme_], $self->[dropper_], \$self->[server_], undef, undef, $self->[write_], $self->[peer_])= $_[2]->@*;

	$self->[recursion_count_]=0;
  $self->[in_progress_]=undef;
  $self->[id_]=$id++;
	$self;
}


1;
