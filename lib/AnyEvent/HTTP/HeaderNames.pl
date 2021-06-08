#Generate a list of header names as a hash or array
our @names=qw(
	Access-Control-Allow-Credentials
Access-Control-Allow-Origin
Access-Control-Allow-Headers
Upgrade
Connection
Content-Type
WebSocket-Origin
WebSocket-Location
Sec-WebSocket-Origin
Sec-Websocket-Location
Sec-WebSocket-Key
Sec-WebSocket-Accept
Sec-WebSocket-Protocol
DataServiceVersion
);

use enum @names;
