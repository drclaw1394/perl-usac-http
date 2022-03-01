package uSAC::HTTP::StateCookie;
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


use Data::Dumper;

our @EXPORT_OK=qw<state_cookie state_cookie_in state_cookie_out>;
our @EXPORT=();
our %EXPORT_TAGS=(
	"all"=>[@EXPORT_OK]
);

#Inner and outerware to get/set/update cookie with state


#Middleware constructor, returns inner and outer
sub state_cookie {
	my %options=@_;

	[state_cookie_in(%options), state_cookie_out(%options)];
}

sub state_cookie_in {
	my %options=@_;
	my $state_decode=$options{decode};

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
			if($state_value=$rex->cookies->{$state_name}){
				eval {
					$rex->state->{$state_field}=$state_decode->(decode_base64url($state_value))
				};
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
	my $state_encode=	$options{encode};
	my $state_name=		$options{name}//"USAC_STATE_ID";
	my $state_field=	$options{field}//"state_cookie";

	sub {
		my $outer_next=shift;

			sub {
				#route, rex, code, headers, body
				my $rex=$_[1];

				#If the field exists but is an empty string, then expire the cookie to delete it
				#if field doesnt exists do nothing
				#if it exisits and defined write state

				#Encode the data if it is defined and we have an encoding function
				for($rex->state->{$state_field}){
					$_//return &$outer_next;# Undefined do nothing
					if($_){
						if(my $encoded=encode_base64url $state_encode->($_)){
							push $_[3]->@*,
							HTTP_SET_COOKIE,
								new_cookie($state_name=>$encoded)
								->serialize_set_cookie
							;
						}
					}
					elsif($_ eq ""){
						push $_[3]->@*,
						#expire the cookie
						map((HTTP_SET_COOKIE, $_->serialize_set_cookie), expire_cookies $state_name);

					}
				}
				&$outer_next;
			}
	}
}
1;
