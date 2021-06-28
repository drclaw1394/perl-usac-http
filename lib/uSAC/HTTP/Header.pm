#Generate a list of header names as a hash or array
package uSAC::HTTP::Header;
use Exporter 'import';
BEGIN {
	our @names=qw(
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
		Connection
		Content-Encoding
		Content-Language
		Content-Length
		Content-Location
		Content-MD5
		Content-Range
		Content-Type
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

		Referer
		Retry-After
		Server
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
		Sec-Websocket-Location
		Sec-WebSocket-Key
		Sec-WebSocket-Accept
		Sec-WebSocket-Protocol
		DataServiceVersion
	);
	our @const_names=map {(("HTTP_".uc)=~s/-/_/gr, $_)} @names;
};
#use enum (@const_names); 		#Make indexes, with underscores
#our %hash=map {$names[$_]=>$_} 0..@names-1;	#Map actual names to indexes, for parsing

use constant {@const_names}; #Direct constants to use
our @EXPORT_OK=@const_names;
our %EXPORT_TAGS=(
	constants=>\@const_names
);
1;
