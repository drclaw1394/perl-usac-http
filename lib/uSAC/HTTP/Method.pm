package uSAC::HTTP::Method;
use Exporter 'import';

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
	our @const_names=map {("HTTP_".uc $names[$_], $names[$_])} 0..@names-1;
}

#Create Enumerations 
#use enum (map s/ |-|'/_/gr, @names);

#Create constant strings of the form:
#HTTP_GET=>"GET"
use constant {@const_names}; 
our @EXPORT_OK=@const_names;
our %EXPORT_TAGS=(
		constants=>\@const_names

);
1;
