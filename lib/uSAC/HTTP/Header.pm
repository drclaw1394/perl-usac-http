#Generate a list of header names as a hash or array
package uSAC::HTTP::Header;
use strict;
use warnings;
use feature qw<refaliasing fc>;
no warnings qw<experimental>;
use List::Util qw<first>;
use Exporter 'import';
use Log::ger;
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
		Sec-Websocket-Location
		Sec-WebSocket-Key
		Sec-WebSocket-Accept
		Sec-WebSocket-Protocol
		Sec-WebSocket-Extensions
		DataServiceVersion
	);
	%const_names=map {(("HTTP_".uc)=~s/-/_/gr, $_)} @names;

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
our @EXPORT_OK=(keys(%const_names), "find_header");
our %EXPORT_TAGS=(
	constants=>["find_header", keys %const_names]
);

my @key_indexes=map {$_*2} 0..99;
sub find_header_old: lvalue {
	\my @headers=$_[0];
	my $key=$_[1];
	#print "Searching for key $key\n";
	#print @headers;
	my $index=first {$headers[$_] == $key} @key_indexes;
	#print $index."\n";
	return $headers[($index//-2)+1];
	#?$headers[$index+1]:undef;


}
sub find_header: lvalue{
	#my($headers, $key)=@_;	
	\my @headers=$_[0];
	for my $k (@key_indexes){
		return undef if $k >=@headers;
		CONFIG::log and do {
			log_trace "iteration key is $k, search key is $_[1]";
			log_trace "serching through headers: ".$index_to_name[$headers[$k]]//$headers[$k];
			log_trace "lable: $headers[$k]";
		};
		$headers[$k] == $_[1] and return $headers[$k+1];
	}
}

1;
