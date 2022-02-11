use uSAC::HTTP;
use uSAC::HTTP::Middleware qw<log_simple log_simple_in log_simple_out>;
#use uSAC::HTTP::StateCookie qw<state_cookie state_cookie_in state_cookie_out>;
use uSAC::HTTP::State::JSON ":all";
use uSAC::HTTP::State::UUID ":all";
use Data::Dumper;


my $server;
$server=usac_server {
	usac_middleware log_simple dump_headers=>1;
	usac_middleware state_json;		#defualt setup for state in cookie (b64 json)
	usac_middleware state_uuid;
        ###########################################################################
        # usac_middleware state_cookie(           #setting up a session id string #
        #         name=>"SESSIONID",                                              #
        #         field=>"session_id",                                            #
        #         decode=>sub {                                                   #
        #                 $_[0]//time;                                            #
        #         },                                                              #
        #         encode=>sub {                                                   #
        #                 $_[0];                                                  #
        #         }                                                               #
        # );                                                                      #
        ###########################################################################
	my $port=8080;
	usac_host "localhost:$port";

	usac_site {
		usac_id "state testing";
		usac_prefix "testing";
		usac_route page1=>sub {
			my $state= &rex_state_json_data//={};

			$state->{time}=time;
			$state->{page1_visited}=1;
			
			&rex_state_uuid_data//=state_uuid_new;

			rex_reply @_, HTTP_OK, [], Dumper(&rex_state);
		};

		usac_route page2=> sub {
			my $state=&rex_state;#$_[1]->state;
			rex_reply @_, HTTP_OK, [], Dumper $state;
		};

		usac_route clear=> sub {
			#$_[1]->state->{session_id}="";
			&rex_state_uuid_data="";	#Clear with setting a empty string
							#Setting undef will prevent encoding output
			&rex_state_json_data="";
			my $state=$_[1]->state;
			rex_reply @_, HTTP_OK, [], Dumper $state;
		};

		usac_route re=>sub {
			rex_redirect_internal @_, rex_site_url @_, "page1";
		};

		usac_route temp=>sub {
			rex_redirect_temporary @_, rex_site_url @_, "page1";
		};
	};

	usac_site {
		usac_route POST=>"test/$File_Path"=>usac_form_slurp root=>usac_dirname, sub {
			say my ($matcher, $rex, $fields, $last)=@_;
			rex_reply $matcher, $rex, HTTP_OK, [], "Got test for $1";
		};

		usac_route "/$File_Path"=> usac_file_under root=>usac_dirname, "static";
	}
};

$server->run;
