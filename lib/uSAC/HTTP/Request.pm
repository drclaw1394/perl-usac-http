package uSAC::HTTP::Method;

BEGIN {

	our @names=qw<
		GET
		HEAD
		POST
		PUT
		DELETE
		CONNECT
		OPTIONS
		TRACE
		PATCH
		>;
}

#Create Enumerations 

#Create constant strings of the form:
#HTTP_GET=>"GET"
use constant::more {map {(("HTTP_".uc $names[$_])=~s/ |-/_/gr, $names[$_])} 0..@names-1}; 
1;
