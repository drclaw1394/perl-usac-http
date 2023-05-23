#Generate a list of header names as a hash or array
package uSAC::HTTP::Header;
use strict;
use warnings;
use feature qw<refaliasing fc>;
no warnings qw<experimental>;
use List::Util qw<first>;
use Exporter 'import';
use Log::ger;
use Log::OK;
our %const_names;
our @index_to_name;
BEGIN {
	our @names=qw(
		_unkown_
		Accept
		Accept-Charset
		Accept-Encoding
		Accept-Language
		Accept-Ranges
		Age
		Allow
		Authorization

		Access-Control-Allow-Credentials
		Access-Control-Allow-Origin
		Access-Control-Allow-Headers
		Cache-Control
    Cookie
		Connection
		Content-Encoding
		Content-Language
		Content-Length
		Content-Location
		Content-MD5
		Content-Range
		Content-Type
		Content-Disposition
		Date
		ETag
		Expect
		Expires
		From
		Host
		If-Match
		If-Modified-Since
		If-None-Match
		If-Range
		If-Unmodified-Since
		Keep-Alive
		Last-Modified
		Location
		Max-Forwards
		Pragma
		Proxy-Authenticate
		Proxy-Authorization

		Range

		Referer
		Retry-After

		Server
		Set-Cookie
		TE
		Trailer
		Transfer-Encoding
		Upgrade
		User-Agent
		Vary
		Via
		Warning
		WWW-Authenticate
		WebSocket-Origin
		WebSocket-Location
		Sec-WebSocket-Origin
		Sec-WebSocket-Location
		Sec-WebSocket-Key
		Sec-WebSocket-Accept
    Sec-WebSocket-Version
		Sec-WebSocket-Protocol
		Sec-WebSocket-Extensions
		DataServiceVersion

    :Method
    :Scheme
    :Path
    :Authority
    :Status
	);

	%const_names=map {(("HTTP_".uc)=~s/-|:/_/gr, lc $_)} @names;

	my $i=0;
	#our %const_names=map {(("HTTP_".uc)=~s/-/_/gr, $i++)} @names;

	#Resolve index to name string
	@index_to_name=@names;#map fc, @names;
	$index_to_name[0]=undef;

	#Resolve name string to index
	#our %name_to_index=map { uc($index_to_name[$_])=>$_ } 0..$#index_to_name;
	#
};

use constant \%const_names; #Direct constants to use
#use constant \%name_to_index;

our @EXPORT_OK=(keys(%const_names));

our %EXPORT_TAGS=(
	constants=>[keys %const_names]
);


1;
