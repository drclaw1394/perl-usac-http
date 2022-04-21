package uSAC::HTTP::State::UUID;
#Module for storting a uuid in http sate
use strict;
use warnings;


use Log::ger;
use Log::OK;

use Exporter 'import';
use feature qw<refaliasing say state current_sub>;
no warnings "experimental";
no feature "indirect";

use Time::HiRes qw<time>;
use Data::UUID;
use uSAC::HTTP::StateCookie qw<state_cookie>;

use Data::Dumper;

our @EXPORT_OK=qw<state_uuid rex_state_uuid_data state_uuid_new state_uuid_data>;
our @EXPORT=();
our %EXPORT_TAGS=(
	"all"=>[@EXPORT_OK]
);

my $ug=Data::UUID->new;

my $name="USACUUID";
my $field="uuid";

sub state_uuid {
	my %options=@_;
	state_cookie(		#setting up a session id string	
		name=>$options{name}//$name,
		field=>$options{field}//$field,

		decode=>sub {
			$_[0]||undef;	#make empty string an undef
		},
		encode=>sub {
			$_[0];
		}
	);
}

sub state_uuid_new{
	$ug->create_str();
}

sub rex_state_uuid_data : lvalue{
	$_[1]->state->{$_[2]//$field};
}

1;

