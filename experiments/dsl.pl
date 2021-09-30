use strict;
use warnings;
use feature qw<switch state say declared_refs refaliasing>;
no warnings "experimental";

use uSAC::HTTP;
use uSAC::HTTP::Code qw<:constants>;
use uSAC::HTTP::Header qw<:constants>;
use uSAC::HTTP::Rex;
use uSAC::HTTP::Server;
use uSAC::HTTP::Middleware ":all";
use uSAC::HTTP::Static;
use Template::Vanilla;
use Data::Dumper;
$Data::Dumper::Maxdepth=1;
my $templates=Template::Vanilla->new();


my $server; $server=usac_server {
	
	usac_interface "0.0.0.0";	#adds a interface to to bind on 
	usac_port 8080;			#Add a port to bind on
	usac_hosts 1;			#Turn on virtual hosts
	usac_sub_product "myserver/1";
	

	#adding more sites
	usac_site {
		usac_id 	"My Site";		#Descriptive name of site
		usac_host 	"localhost:8080";	#Host we will match
		usac_prefix 	"/sub";			#Prefix if applicable
		usac_innerware 
		#log_simple,
				state_simple(on_new=>sub {{new=>1,time=>time}})
				;		#Middleware common to all routes

		#routes
		usac_route 	GET=>'/hello$'=>static_content "Sub site";
		usac_route	GET=>'/hello_logged'=>(log_simple)=>static_content "Logged";
		usac_route 	GET=>"/public$Path"=>static_file_from "data";
		#usac_route 	GET=>"/public$Path"=>static_file_from "data";

		
		usac_site {
			usac_prefix "/more";
			usac_id "two deep";
			usac_route "/data"=>static_content "Two deep";
		};
	};

	#defining routes on the default site. This will match any host so need to go last
	usac_route GET=>"/\$"=>		static_content txt=>"Hello there";
	usac_route GET=>'/hello$'=>	static_content "Hello Again";
	usac_route GET=>'/chunked$'=>	sub { rex_reply @_, HTTP_OK, [], [qw<data to chunk>]};
	usac_route '/shortcut'=>	static_content html=>"shortcut";

        ############################################################################
        # usac_route POST=>'/upload$'=>sub {                                     #
        #         my (undef, $rex)=@_;                                             #
        #         rex_form_upload @_, sub {                                        #
        #                 #section data, section header, last for section          #
        #                 state $headers=0;                                        #
        #                 state $fields;                                           #
        #                 if($headers==$_[1]){                                     #
        #                         #same headers=>same part                         #
        #                         say "Same headers.. Continuation";               #
        #                 }                                                        #
        #                 else {                                                   #
        #                         #new headers new part                            #
        #                         say "New headers.. new part";                    #
        #                         #parse form params and process acculatead data.  #
        #                         $headers=$_[1];                                  #
        #                         $fields=rex_parse_form_params $rex, @_;          #
        #                         say %$fields;                                    #
        #                 }                                                        #
        #                 if($_[2]){                                               #
        #                         #that was the last section                       #
        #                         say "processed last part";                       #
        #                         rex_reply_simple undef, $rex, HTTP_OK,[],'yay';; #
        #                 }                                                        #
        #         }                                                                #
        #                                                                          #
        # };                                                                       #
        #                                                                          #
        # usac_route POST=>'/upload2$'=>sub {                                    #
        #         my (undef, $rex)=@_;                                             #
        #         rex_urlencoded_upload @_, sub {                                  #
        #                 #section data, section header, last for section          #
        #                 state $headers=0;                                        #
        #                 state $fields;                                           #
        #                 if($headers==$_[1]){                                     #
        #                         #same headers=>same part                         #
        #                         say "Same headers.. Continuation";               #
        #                 }                                                        #
        #                 else {                                                   #
        #                         #new headers new part                            #
        #                         say "New headers.. new part";                    #
        #                         $headers=$_[1];                                  #
        #                         $fields=rex_parse_form_params $rex, @_;          #
        #                         say %$fields;                                    #
        #                 }                                                        #
        #                 if($_[2]){                                               #
        #                         #that was the last section                       #
        #                         say "processed last part";                       #
        #                         rex_reply_simple undef, $rex, HTTP_OK,[],'yay';; #
        #                 }                                                        #
        #         }                                                                #
        # };                                                                       #
        #                                                                          #
        # usac_route POST=>'/upload3$'=>sub {                                    #
        #         my (undef, $rex)=@_;                                             #
        #         rex_handle_form_upload @_, undef, sub {                          #
        #                 #section data, section header, last for section          #
        #                 state $headers=0;                                        #
        #                 state $fields;                                           #
        #                 if($headers==$_[1]){                                     #
        #                         #same headers=>same part                         #
        #                         say "Same headers.. Continuation";               #
        #                 }                                                        #
        #                 else {                                                   #
        #                         #new headers new part                            #
        #                         say "New headers.. new part";                    #
        #                         $headers=$_[1];                                  #
        #                         $fields=rex_parse_form_params $rex, @_;          #
        #                         say %$fields;                                    #
        #                 }                                                        #
        #                 if($_[2]){                                               #
        #                         #that was the last section                       #
        #                         say "processed last part";                       #
        #                         rex_reply_simple undef, $rex, HTTP_OK,[],'yay';; #
        #                 }                                                        #
        #         };                                                               #
        # };                                                                       #
        ############################################################################

	usac_route POST=> "/multipart" => rex_stream_multipart_upload sub {
		say "multipart";
		#0=> line/undef
		#1=> rex
		#2=> data
		#3=> part headers
		#4=> last flag

		my $rex=$_[1];
		if($_[4]){
			
			rex_reply_simple undef, $rex, HTTP_OK,[], "multipart uploaded";
		}
	};

	usac_route POST=> "/urlencoded" => rex_stream_urlencoded_upload  sub {
		my $rex=$_[1];
		say $_[2];
		if($_[4]){
			rex_reply_simple undef, $rex, HTTP_SEE_OTHER,[[HTTP_LOCATION,'/progress']], "urlencoded uploaded";
		}
		
	};

	usac_route POST=> "/form\$" =>(log_simple)=> rex_stream_form_upload  sub {
		my $rex=$_[1];
		say $rex;
		if($_[4]){
			rex_reply_simple undef, $rex, HTTP_OK,[], "form uploaded";
		}
	};

	usac_route POST=> "/uploader"=> rex_save_to_file  dir=>"uploads2",prefix=>"aaa",mime=>undef, sub {
		#0=>line
		#1=>rex
		#2=> $filename
		#3=> last flag
		my $rex=$_[1];
		say "Rex: $rex";
		if($_[3]){
			say "File $_[2] was saved";
			rex_reply_simple undef, $rex, HTTP_OK, [], "files uploaded to disk";
		}
	};

	usac_route POST=> "/form_file"=> rex_save_form_to_file  dir=>"uploads2",prefix=>"aaa", sub {

		my $rex=$_[1];
		my $fields=$_[2];
		say "save form to file cb ",Dumper $fields;
		rex_reply_simple undef, $rex, HTTP_OK,[], "files uploaded to disk";
	};

	usac_route POST=> "/form_url"=> rex_save_form  sub {

		my $rex=$_[1];
		my $fields=$_[2];
		say "save form ",Dumper $fields;
		rex_reply_simple undef, $rex, HTTP_OK,[], "url form uploaded";
	};

	usac_route "/cmd"=>sub {
		#form sub mission via GET
		my $kv=$_[1]->query;#rex_parse_query_params $_[1];
		#my $kv=rex_parse_query_params $_[1];
		#say $kv->%*;
		rex_reply_simple @_, HTTP_OK,[],"yarrrp";
	};

	usac_route ["GET","POST"]=>"/arrayref"=>static_content "got array ref";


	#Login processing
	usac_route "GET"=>"/login\$"=>sub {
		say @_;
		push @_, "/login.htmlt";
		&{static_file_from "data"};
	};

	usac_route "POST"=>"/login\$"=> rex_save_web_form sub {
		pop;			#last flag
		say Dumper pop;		#fields from form
		#say Dumper @_;

		#rex_reply_simple @_, HTTP_OK, [], "yarrrp";
		usac_redirect_see_other @_, "/progress";
		#rex_reply_simple @_, HTTP_SEE_OTHER,[[HTTP_LOCATION,'/progress']], "yarp";

	};

	usac_route "/progress"=>sub {
		rex_reply_simple @_, HTTP_OK, [], "progress page";
	};

	#end login processing

	usac_route "/template"=>sub {
		my $buf="";
		include "./templates/login.vpl", $templates, \$buf, @_;
		rex_reply_simple @_, HTTP_OK, [], $buf;
	};

	usac_route POST=>"/template"=>(log_simple)=>rex_save_web_form sub {
		#say "END FORM CALLBACK";
		pop;	#last flag
		say Dumper pop;	#form kvey value hash
		usac_redirect_see_other @_, "/progress";
	};
};

$server->run;
