use strict;
use warnings;
use Hustle::Table;

#linked routing groups per  level?


# a single hustle table with cached lookup would be quickest

#deny 
#	return not authorised
#allow
#
#public	
#	No authentication checking

#cors
#	Public but with cors checking
#

#restricted
#	Authenticated users only

#kk, allow based on url directly


#
#HOSTMATCH && hostmatch 
#and CORMATCH and accesscontrol
#and IPMATCH and ipok
#
#virtual host table	#host header checking
#	branch/mount table	#mount part of a site  at a location
#			
#		

#match Method, ($mount)path, version

sub route_rex {
	#prepend hostname, method, /$mount/  path/
	#if no hostname then
	#
}

location 
	matcher		#Matching the request/response line ie "GET /Hello"
	=>innerware	#List of incomming  middleware (innerware) to process before end point
	=>sub {};	#endpoiint	


location (host=>"asdf", method=>"GET", mount=> mount, path=>path)
host defaults to ""
method defaults to GET
mount defaults to ""
path is required

Adds an entry to the host lookup table?
	or have hosts middleware? which has its own lookup table
