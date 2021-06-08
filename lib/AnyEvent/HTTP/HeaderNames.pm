#Generate a list of header names as a hash or array
package AnyEvent::HTTP::HeaderNames;
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
};

use enum (map s/-/_/gr, @names); #Make indexes, with underscores
1;
