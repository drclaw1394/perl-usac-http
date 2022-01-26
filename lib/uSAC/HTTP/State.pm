package uSAC::HTTP::State;
use strict;
use warnings;
use Exporter 'import';
use feature qw<refaliasing say state current_sub>;
no warnings "experimental";
no feature "indirect";
use uSAC::HTTP::Cookie qw<:all>;
use uSAC::HTTP::Code qw<:constants>;
use uSAC::HTTP::Header qw<:constants>;
use uSAC::HTTP::Cookie;


use MIME::Base64 qw<encode_base64url decode_base64url>;
use JSON;


use Data::Dumper;

our @EXPORT_OK=qw<state_cookie state_cookie_in state_cookie_out>;
our @EXPORT=();
our %EXPORT_TAGS=(
	"all"=>[@EXPORT_OK]
);

#configure basic session management
#Basic access to cookies used in client/server.
#The cookie keys used are up to the user, as is how the data is authenticated and expired.
#
#For example a simple memory based session:
# A hash with the session id to session object is stored in memory
# 	The fields of the object include
# 		the session id
# 		username
# 		password hash
# 		expiry time
#
# When a request comes in on a managed url, the cookies are parsed.
# 	If no value is present:
# 		A new state/session is created in memory. Only the session, expiry and authenticated are stored
#
#	If a value is present:
#		The session data is retrieved and stored in the rex object
#
#
# 	if the session tag is present
# the value is sent to the authenticate callback for the user code to authenticate. The arguement passed is
#  the decoded value
# 
# The user callback authenticates the session_id (or not)
#  
#
#

#state info stored in a cookie
#could just be a session id
#could be a token will authentication info

sub state_cookie {
	my %options=@_;

	[state_cookie_in(%options), state_cookie_out(%options)];
}

sub state_cookie_in {
	#given a hash ref to store the state
	#state $defualt_store={};
	my %options=@_;

	my $state_decode=$options{decode}//sub {
		return undef unless $_[0];
		my $d=decode_json $_[0];
		unless($d){
			$d={};
		}
		$d;
	};
	my $state_name=		$options{name}//"USAC_STATE_ID";
	my $state_field=	$options{field}//"state_cookie";

	sub {
		my $inner_next=shift;

		#input sub
		#Extract the cookie with the right key
		sub {
			#route, rex, 
			my ($route, $rex)=@_;
			my $state_value;
			$state_value=$rex->cookies->{$state_name};	
			#say "Encoded incoming state value, $state_value";
			#Do a call to trigger retreval or create on a state
			#On completion this will call the  the next sub to continue 
			#the innerware. Allows async behaviour when talking to and external server
			#Rex is passed as an argument so state is manipuated directly
			if($state_decode){
				$rex->state->{$state_field}=$state_decode->($state_value?decode_base64url($state_value):"");
			}
			else {
				#raw state stored in rex state
				$rex->state->{$state_field}=$state_value;
			}
			&$inner_next;
		}


	}
}

sub state_cookie_out {
	#given a hash ref to store the state
	#state $defualt_store={};
	my %options=@_;

	#my $states=$options{store}//$defualt_store;
	my $state_encode=	$options{encode}//sub {encode_json $_[0]};
	my $state_name=		$options{name}//"USAC_STATE_ID";
	my $state_field=	$options{field}//"state_cookie";

	sub {
		my $outer_next=shift;

			sub {
				#route, rex, code, headers, body
				my $rex=$_[1];

				#Add Set cookie to the headers, if state is defined
				#Returns undef on error or if no change in state
				#TODO: only encode cookie if the state has changed
				if(my $encoded=encode_base64url $state_encode->($rex->state->{$state_field})){
                                       push $_[3]->@*,
                                        [HTTP_SET_COOKIE,
                                                new_cookie($state_name=>$encoded)
                                                ->serialize_set_cookie
                                        ];
				}
				&$outer_next;
			}
	}
}
1;
