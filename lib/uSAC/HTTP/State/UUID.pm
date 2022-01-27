package uSAC::HTTP::State::UUID;
#Module for storting a uuid in http sate
use strict;
use warnings;
use Exporter 'import';
use feature qw<refaliasing say state current_sub>;
no warnings "experimental";
no feature "indirect";

use Time::HiRes qw<time>;
use uSAC::HTTP::StateCookie qw<state_cookie>;

use Data::Dumper;

our @EXPORT_OK=qw<state_uuid state_uuid_new state_uuid_data>;
our @EXPORT=();
our %EXPORT_TAGS=(
	"all"=>[@EXPORT_OK]
);

my $name="SESSIONID";
my $field="session_id";

sub state_uuid {
	my %options=@_;
	state_cookie(		#setting up a session id string	
		name=>"SESSIONID",
		field=>"session_id", 
		decode=>sub {
			$_[0]//time;
		},
		encode=>sub {
			say "doing encode for UUID: $_[0]";
			$_[0];
		}
	);
}

sub state_uuid_new{
	#TODO: update to an actual UUID
	(time."") =~ s/\.//r
}

sub state_uuid_data : lvalue{
	$_[1]->state->{$field};
}

1;

