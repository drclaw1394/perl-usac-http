package uSAC::HTTP::Middleware::State::JSON;
#Module for storting a uuid in http sate
use strict;
use warnings;
use Exporter 'import';
use feature qw<refaliasing say state current_sub>;
no warnings "experimental";
no feature "indirect";

use Time::HiRes qw<time>;
use uSAC::HTTP::StateCookie qw<state_cookie>;
use JSON;


our @EXPORT_OK=qw<state_json rex_state_json_data>;
our @EXPORT=();
our %EXPORT_TAGS=(
	"all"=>[@EXPORT_OK]
);

my $name="USACJSON";
my $field="json";

#Middleware to decode/encode state stored as json in a cookie.
#
sub state_json {
	my %options=@_;
	state_cookie(		#setting up a session id string	
		name=>$options{name}//$name,
		field=>$options{field}//$field,

		#Decodes json to hash/array
		decode=> \&decode_json,
                ######################################
                # sub {                              #
                #         return undef unless $_[0]; #
                #         decode_json $_[0];         #
                # },                                 #
                ######################################
		#Encode hash/array to json
		encode=> \&encode_json
		#sub {encode_json $_[0]}
	);
}

sub rex_state_json_data : lvalue{
        $_[1]->state->{$_[2]//$field};
}

1;

