use v5.36;
package uSAC::HTTP::Code;
no warnings "experimental";


our @names;
our @values;
our %const_names;
BEGIN {

	our @lookup=(
		#Information responses
		"Continue"=>100,
		"Switching Protocols"=>101,
		"Processing"=>102,
		"Early Hints"=>103,

		#Successful response
		"OK"=>200,
		"Created"=>201,
		"Accepted"=>202,
		"Non-Authoritative Information"=>203,
		"No Content"=>204,
		"Reset Content"=>205,
		"Partial_Content"=>206,
		"Multi-Staus"=>207,
		"Already Reported"=>208,
		"IM Used"=>226,

		#Redirection messages
		"Multiple Choice"=>300,
		"Moved Permanently"=>301,
		"Found"=>302,
		"See Other"=>303,
		"Not Modified"=>304,
		"Temporary Redirect"=>307,
		"Permanent Redirect"=>308,

		#Client error responses
		"Bad Request"=>400,
		"Unauthorized"=>401,
		"Payment Required"=>402,
		"Forbidden"=>403,
		"Not Found"=>404,
		"Method Not Allowed"=>405,
		"Not Acceptable"=>406,
		"Proxy Authentication Required"=>407,
		"Request Timeout"=>408,
		"Conflict"=>409,
		"Gone"=>410,
		"Length Required"=>411,
		"Precondition Failed"=>412,
		"Payload Too Large"=>413,
		"URI Too Long"=>414,
		"Unsupported Media Type"=>415,
		"Range Not Satisfiable"=>416,
		"Expectation Failed"=>417,
		"I'm a teapot"=>418,
		"Misdirected Request"=>421,
		"Unprocessable Entity"=>422,
		"Locked"=>423,
		"Failed Dependency"=>424,
		"Too Early"=>425,
		"Upgrade Required"=>426,
		"Precondition Required"=>428,
		"Too Many Requests"=>429,
		"Request Header Fields Too Large"=>431,
		"Unavailable For Legal Reasons"=>451,

		#Server error Responses
		"Internal Server Error"=>500,
		"Not Implemented"=>501,
		"Bad Gateway"=>502,
		"Service Unavailable"=>503,
		"Gateway Timeout"=>504,
		"HTTP Version Not Supported"=>505,
		"Variant Also Negotiates"=>506,
		"Insufficent Storage"=>507,
		"Loop Detected"=>508,
		"Not Extended"=>510,
		"Network Authentication Required"=>511,
	);

	@names= map {$lookup[$_*2]} 0..@lookup/2-1; 
	@values= map {$lookup[1+$_*2]} 0..@lookup/2-1; 
  %const_names=map {(("HTTP_".uc $names[$_])=~s/ |-|'/_/gr,
    "$values[$_]")} 0..@names-1;
	
	#build value to code array
	our @code_to_name;
  #for my $p (pairs(@lookup)){
  for my ($k,$v)(@lookup){
    my $p=[$k,$v];
		$code_to_name[$p->[1]]=$p->[0];
	}
	
}

use constant::more \%const_names; #Direct constants to use
use Export::These keys(%const_names);#,constants=>[keys %const_names];
1;
