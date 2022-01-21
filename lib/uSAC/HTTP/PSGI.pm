package uSAC::HTTP::PSGI;
use strict;
use warnings;
use feature qw<switch say refaliasing state>;
no warnings "experimental";


use uSAC::HTTP;
use uSAC::HTTP::Rex;
use uSAC::HTTP::Session;

use constant KEY_OFFSET=>0;
use enum ("entries_=".KEY_OFFSET, qw<end_>);
use constant KEY_COUNT= end_-entries_+1;

sub new {
	
	
}

#read needs to be converted from push to pull
#Buffer reads
sub read {
	my ($self,undef,$length, $offset)=@_;
	\my $buf=\$_[1];	#alias buffer

	#if no entries in the queue we need to

}


sub write {
	my ($self)=@_;
}

#Driver to interface with PSGI based applications
#this acts as either middleware or an end point
sub psgi_adaptor {

	sub {
		my ($route, $rex)=@_;

		state $psgi_version=[1,1];

		\my %env=\$rex->[uSAC::HTTP::Rex::headers_];	#alias the headers as the environment

		#The HTTP request method, such as "GET" or "POST". This
		#MUST NOT be an empty string, and so is always
		#required.
		#
		$env{REQUEST_METHOD}=	$rex->[uSAC::HTTP::Rex::method_];

		#The initial portion of the request URL's path,
		#corresponding to the application. This tells the
		#application its virtual "location". This may be an
		#empty string if the application corresponds to the
		#server's root URI.
		#
		#If this key is not empty, it MUST start with a forward slash (/).
		#
		$env{SCRIPT_NAME}=		"";

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
		$env{PATH_INFO}=		"";

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
		$env{REQUEST_URI}=		$rex->[uSAC::HTTP::Rex::uri_];

		#The portion of the request URL that follows the ?, if
		#any. This key MAY be empty, but MUST always be
		#present, even if empty.
		#
		$env{QUERY_STRING}=		"";

		#When combined with SCRIPT_NAME and PATH_INFO, these
		#keys can be used to complete the URL. Note, however,
		#that HTTP_HOST, if present, should be used in
		#preference to SERVER_NAME for reconstructing the
		#request URL.
		$env{SERVER_NAME}=		"";
		$env{SERVER_PORT}=		"";

		#The version of the protocol the client used to send
		#the request. Typically this will be something like
		#"HTTP/1.0" or "HTTP/1.1" and may be used by the
		#application to determine how to treat any HTTP request
		#headers.
		#
		$env{SERVER_PROTOCOL}=	$rex->[uSAC::HTTP::Rex::version_];


		#The length of the content in bytes, as an integer. The
		#presence or absence of this key should correspond to
		#the presence or absence of HTTP Content-Length header
		#in the request.
		#

		#CONTENT_LENGTH=>	"",

		#The request's MIME type, as specified by the client.
		#The presence or absence of this key should correspond
		#to the presence or absence of HTTP Content-Type header
		#in the request.
		#
		#CONTENT_TYPE=>		"",


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
		$env{'psgi.version'}=	$psgi_version;

		# A string http or https, depending on the request URL.
		#
		$env{'psgi.url_scheme'}=	"";

		# the input stream.
		$env{'psgi.input'}=		"";

		# the error stream.
		$env{'psgi.errors'}=		"";

		# This is a boolean value, which MUST be true if the
		# application may be simultaneously invoked by another
		# thread in the same process, false otherwise.
		#
		$env{'psgi.multithreaded'}=	"";

		#This is a boolean value, which MUST be true if an
		#equivalent application object may be simultaneously
		#invoked by another process, false otherwise.
		#
		$env{'psgi.multiproess'}=	"";

		#A boolean which is true if the server expects (but
		#does not guarantee!) that the application will only be
		#invoked this one time during the life of its
		#containing process. Normally, this will only be true
		#for a server based on CGI (or something similar).
		#
		$env{'psgi.run_once'}=	"";

		#A boolean which is true if the server is calling the
		#application in an non-blocking event loop.
		#
		$env{'psgi.nonblocking'}= 	"";

		#A boolean which is true if the server supports
		#callback style delayed response and streaming writer
		#object.
		#
		$env{'psgi.streaming'}=	"";

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



		#EXTENSIONS
		#The raw IO socket to access the client connection to
		#do low-level socket operations. This is only available
		#in PSGI servers that run as an HTTP server, and should
		#be used when (and only when) you want to jailbreak out
		#of PSGI abstraction, to implement protocols over HTTP
		#such as BOSH or WebSocket.
		#
		$env{'psgix.io'}= "";

		#A boolean which is true if the HTTP request body (for
		#POST or PUT requests) is buffered using a temporary
		#filehandle or PerlIO in psgi.input. When this is set,
		#applications or middleware components can safely read
		#from psgi.input without worrying about non-blocking
		#I/O and then can call seek to rewind the input for the
		#transparent access.
		#
		$env{'psgix.input.buffered'}="";

		#A code reference to log messages. The code reference
		#is passed one argument as a hash reference that
		#represents a message to be logged. The hash reference
		#MUST include at least two keys: level and message
		#where level MUST be one of the following strings:
		#debug, info, warn, error and fatal. message SHOULD be
		#a plain string or a scalar variable that stringifies.
		#
		$env{'psgix.logger'}=		"";

		#A hash reference for storing and retrieving session
		#data. Updates made on this hash reference SHOULD be
		#persisted by middleware components and SHOULD be
		#restored in the succeeding requests. How to persist
		#and restore session data, as well as how to identify
		#the requesting clients are implementation specific.
		#
		$env{'psgix.session'}=		"";


		#A hash reference to tell Middleware components how to
		#manipulate session data after the request. Acceptable
		#keys and values are implementation specific.
		#
		$env{'psgix.session.options'}="";

		#A boolean which is true if the PSGI server supports
		#harakiri mode, that kills a worker (typically a forked
		#child process) after the current request is complete.
		#
		$env{'psgix.harakiri'}=		"";

		# A boolean which is set to true by the PSGI
		# application or middleware when it wants the server to
		# kill the worker after the current request.
		#

		$env{'psgix.harakiri.commit'}=		"";

		#A boolean flag indicating whether a PSGI server
		#supports cleanup handlers. Absence of the key assumes
		#false (i.e. unsupported). Middleware and applications
		#MUST check this key before utilizing the cleanup
		#handlers.
		#
		$env{'psgix.cleanup'}="";

		#Array reference to stack callback handlers. This
		#reference MUST be initialized as an empty array
		#reference by the servers. Applications can register
		#the callbacks by simply push()ing a code reference to
		#this array reference. Callbacks will be called once a
		#request is complete, and will receive $env as its
		#first argument, and return value of the callbacks will
		#be simply ignored. An exception thrown inside
		#callbacks MAY also be ignored.

		#If the server also supports psgix.harakiri, it SHOULD
		#implement in a way that cleanup handlers run before
		#harakiri checker, so that the cleanup handlers can
		#commit the harakiri flag.


		$env{'psgix.cleanup.handlers'}=	"";
	};
}

1;
