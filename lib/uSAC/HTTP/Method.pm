package uSAC::HTTP::Method;
use strict;
use warnings;

our %const_names;
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
	%const_names=map {("HTTP_".uc $names[$_], $names[$_])} 0..@names-1;
}

#Create Enumerations 
#use enum (map s/ |-|'/_/gr, @names);

#Create constant strings of the form:
#HTTP_GET=>"GET"
use constant::more \%const_names;

use Export::These keys %const_names;
1;
