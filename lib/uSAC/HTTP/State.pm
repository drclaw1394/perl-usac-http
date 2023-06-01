package uSAC::HTTP::Stateful;
use version; our $VERSION=version->declare("v0.1");
use strict;
use warnings;
use feature qw<state switch refaliasing>;
use uSAC::HTTP::Rex;


#Common. iether a session key, or actual data is stored in a cookie.
#if a session id
#	lookup state in memory
#if a token
#	parse the token and return its data as the state
#
#

sub state {

}

sub state_from_cookie {
	
	
}
sub state_from_token {
}

