use strict;
use warnings;
package uSAC::RTSP::Site;


use Object::Pad;


# Sub class of the uSAC::HTTP::Site class.
# Adds support for rfc2326 which hash this statement
#
#     * RTSP introduces a number of new methods and has a different
#       protocol identifier.
#     * An RTSP server needs to maintain state by default in almost all
#       cases, as opposed to the stateless nature of HTTP.
#     * Both an RTSP server and client can issue requests.
#     * Data is carried out-of-band by a different protocol. (There is an
#       exception to this.)
#     * RTSP is defined to use ISO 10646 (UTF-8) rather than ISO 8859-1,
#       consistent with current HTML internationalization efforts [3].
#     * The Request-URI always contains the absolute URI. Because of
#       backward compatibility with a historical blunder, HTTP/1.1 [2]
#       carries only the absolute path in the request and puts the host
#       name in a separate header field.

my @supported_methods=qw<
  HEAD GET PUT POST PATCH DELETE UPDATE  
  DESCRIBE 
  ANNOUNCE
  GET_PARAMETER
  OPTIONS 
  PAUSE 
  PLAY
  RECORD
  REDIRECT
  SETUP
  SET_PARAMETER
  TEARDOWN
  >;

our $Any_Method	=qr/(?:@{[join "|", @supported_methods]})/;

class uSAC::RTSP::Site :isa(uSAC::HTTP::Site);

method add_route{
  $self->SUPER::add_route(@_); 
}


method any_method{ 

  $Any_Method 
}

method default_method {
  "GET";
}

method supported_methods {
  @supported_methods
}

1;
