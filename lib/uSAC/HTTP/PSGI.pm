use strict;
use warnings;
use feature qw<switch say refaliasing>;
no warnings "experimental";


use uSAC::HTTP;
use uSAC::HTTP::Rex;
use uSAC::HTTP::Session;

#Driver to interface with PSGI based applications
#this acts as either middleware or an end point

sub psgi_adaptor {

	sub {
		my $line=shift;
		my $rex=shift;
		#breakout the required variables 
		my %env=(
			#The HTTP request method, such as "GET" or "POST". This
			#MUST NOT be an empty string, and so is always
			#required.
			#
			REQUEST_METHOD=>	$rex->[uSAC::HTTP::Rex::method_],

			#The initial portion of the request URL's path,
			#corresponding to the application. This tells the
			#application its virtual "location". This may be an
			#empty string if the application corresponds to the
			#server's root URI.
			#
			#If this key is not empty, it MUST start with a forward slash (/).
			#
			SCRIPT_NAME=>		"",

			#The remainder of the request URL's path, designating
			#the virtual "location" of the request's target within
			#the application. This may be an empty string if the
			#request URL targets the application root and does not
			#have a trailing slash. This value should be URI
			#decoded by servers in order to be compatible with RFC
			#3875.
			#
			#If this key is not empty, it MUST start with a forward slash (/).
			#
			PATH_INFO=>		"",
			
			#The undecoded, raw request URL line. It is the raw URI
			#path and query part that appears in the HTTP GET /...
			#HTTP/1.x line and doesn't contain URI scheme and host
			#names.
			#
			#Unlike PATH_INFO, this value SHOULD NOT be decoded by
			#servers. It is an application's responsibility to
			#properly decode paths in order to map URLs to
			#application handlers if they choose to use this key
			#instead of PATH_INFO.
			#
			REQUEST_URI=>		"",

			#The portion of the request URL that follows the ?, if
			#any. This key MAY be empty, but MUST always be
			#present, even if empty.
			#
			QUERY_STRING=>		"",

			#When combined with SCRIPT_NAME and PATH_INFO, these
			#keys can be used to complete the URL. Note, however,
			#that HTTP_HOST, if present, should be used in
			#preference to SERVER_NAME for reconstructing the
			#request URL.
			SERVER_NAME=>		"",
			SERVER_PORT=>		"",

			#The version of the protocol the client used to send
			#the request. Typically this will be something like
			#"HTTP/1.0" or "HTTP/1.1" and may be used by the
			#application to determine how to treat any HTTP request
			#headers.
			#
			SERVER_PROTOCOL=>	"",

			#The length of the content in bytes, as an integer. The
			#presence or absence of this key should correspond to
			#the presence or absence of HTTP Content-Length header
			#in the request.
			#
			CONTENT_LENGTH=>	"",

			#The request's MIME type, as specified by the client.
			#The presence or absence of this key should correspond
			#to the presence or absence of HTTP Content-Type header
			#in the request.
			#
			CONTENT_TYPE=>		"",


			#These keys correspond to the client-supplied HTTP
			#request headers. The presence or absence of these keys
			#should correspond to the presence or absence of the
			#appropriate HTTP header in the request.

			#The key is obtained converting the HTTP header field
			#name to upper case, replacing all occurrences of
			#hyphens - with underscores _ and prepending HTTP_, as
			#in RFC 3875.

			#If there are multiple header lines sent with the same
			#key, the server should treat them as if they were sent
			#in one line and combine them with , , as in RFC 2616.

			#HTTP_HEADERS....
			#
	

			#An array reference [1,1] representing this version of
			#PSGI. The first number is the major version and the
			#second it the minor version.
			#
			'psgi.version'=>	"",

			# A string http or https, depending on the request URL.
			#
			'psgi.url_scheme'=>	"",

			# the input stream.
			'psgi.input'=>		"",

			# the error stream.
			'psgi.errors'=>		"",

			# This is a boolean value, which MUST be true if the
			# application may be simultaneously invoked by another
			# thread in the same process, false otherwise.
			#
			'psgi.multithreaded'=>	"",

			#This is a boolean value, which MUST be true if an
			#equivalent application object may be simultaneously
			#invoked by another process, false otherwise.
			#
			'psgi.multiproess'=>	"",

			#A boolean which is true if the server expects (but
			#does not guarantee!) that the application will only be
			#invoked this one time during the life of its
			#containing process. Normally, this will only be true
			#for a server based on CGI (or something similar).
			#
			'psgi.run_once'=>	"",

			#A boolean which is true if the server is calling the
			#application in an non-blocking event loop.
			#
			'psgi.nonblocking'=> 	"",

			#A boolean which is true if the server supports
			#callback style delayed response and streaming writer
			#object.
			#
			'psgi.streaming'=>	"",
			
			#The server or the application can store its own data
			#in the environment as well. These keys MUST contain at
			#least one dot, and SHOULD be prefixed uniquely.

			#The psgi. prefix is reserved for use with the PSGI
			#core specification, and psgix. prefix is reserved for
			#officially blessed extensions. These prefixes MUST NOT
			#be used by other servers or application. See
			#psgi-extensions for the list of officially approved
			#extensions.

			#The environment MUST NOT contain keys named
			#HTTP_CONTENT_TYPE or HTTP_CONTENT_LENGTH.

			#One of SCRIPT_NAME or PATH_INFO MUST be set. When
			#REQUEST_URI is /, PATH_INFO should be / and
			#SCRIPT_NAME should be empty.  SCRIPT_NAME MUST NOT be
			#/, but MAY be empty.

		);
	};
}

1;
