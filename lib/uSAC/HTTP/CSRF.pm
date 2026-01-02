use strict;
use warnings;

use uSAC::HTTP;
use Exporter "import";


our @EXPORT_OK=qw<csrf_protect>

our @EXPORT=EXPORT_OK;

use Data::UUID;


# This is stored in memory with an expiry time for each entry
# The returned uuid can be used as a hidden field in a form
# When the form is returned, the csrf token can be checked in the map.
# If the associated session id matches that of the in comming request it is valid

# Creates a uuid csrf token and associates it with the uuid of a session and expiry (in a hash)
#
# write header with  token
# retrieve token created
# filter html
sub csrf_protect {
	my %options=@_;
	
	#options include the session field to inspect

	[csrf_protect_in(%options),undef];
}

sub new_csrf_token {
	#return a new uuid which is added into session storage and returned
	#
}

sub csrf_protect_in {
	my %options=@_;
	my $field=$optiions{state_field}//"csrf_token";
	#middleware needs to be added after state	
	sub {
		

	}
}





