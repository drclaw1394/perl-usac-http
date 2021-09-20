use strict;
use warnings;
use feature qw<switch state say>;

use uSAC::HTTP;
use uSAC::HTTP::Code qw<:constants>;
use uSAC::HTTP::Rex;
use uSAC::HTTP::Server;
use uSAC::HTTP::Middleware ":all";
use uSAC::HTTP::Static;
use Template::Vanilla;
use Data::Dumper;
$Data::Dumper::Maxdepth=1;
my $templates=Template::Vanilla->new();


my $server; $server=define_server {
	
	define_interface "0.0.0.0";		#adds a interface to to bind on 
	define_port 8080;			#Add a port to bind on
	set_enable_hosts 1;			#Turn on virtual hosts
	define_sub_product "myserver/1";
	

	#adding more sites
	define_site {
		define_id 	"My Site";		#Descriptive name of site
		define_host 	"localhost:8080";	#Host we will match
		define_prefix 	"/sub";			#Prefix if applicable
		#define_middleware log_simple;		#Middleware common to all routes
		#routes
		define_route 	GET=>'/hello$'=>static_content "Sub site";
		define_route	GET=>'/hello_logged'=>(log_simple)=>static_content "Logged";
		define_route 	GET=>"/public$Path"=>static_file_from "data";
		#define_route 	GET=>"/public$Path"=>static_file_from "data";
		define_site {
			define_prefix "/more";
			define_id "two deep";
			define_route "/data"=>static_content "Two deep";
		};
	};

	#defining routes on the default site. This will match any host so need to go last
	define_route GET=>"/\$"=>static_content txt=>"Hello there";
	define_route GET=>'/hello$'=>static_content "Hello Again";
	define_route GET=>'/chunked$'=>sub { rex_reply @_, HTTP_OK, [], [qw<data to chunk>]};
	define_route '/shortcut'=>static_content html=>"shortcut";

        ############################################################################
        # define_route POST=>'/upload$'=>sub {                                     #
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
        # define_route POST=>'/upload2$'=>sub {                                    #
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
        # define_route POST=>'/upload3$'=>sub {                                    #
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

	define_route POST=> "/multipart" => rex_stream_multipart_upload sub {
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
	define_route POST=> "/urlencoded" => rex_stream_urlencoded_upload  sub {
		my $rex=$_[1];
		say $_[2];
		if($_[4]){
			rex_reply_simple undef, $rex, HTTP_OK,[], "urlencoded uploaded";
		}
		
	};

	define_route POST=> "/form\$" => rex_stream_form_upload  sub {
		my $rex=$_[1];
		if($_[4]){
			rex_reply_simple undef, $rex, HTTP_OK,[], "form uploaded";
		}
	};

	define_route POST=> "/uploader"=> rex_save_to_file  dir=>"uploads2",prefix=>"aaa",mime=>undef, sub {
		#0=>line
		#1=>rex
		#2=> $filename
		#3=> last flag
		my $rex=$_[1];
		say "Rex: $rex";
		if($_[3]){
			say "File $_[2] was saved";
			rex_reply_simple undef, $rex, HTTP_OK,[], "files uploaded to disk";
		}
	};

	define_route POST=> "/form_file"=> rex_save_form_to_file  dir=>"uploads2",prefix=>"aaa", sub {

		my $rex=$_[1];
		my $fields=$_[2];
		say "save form to file cb ",Dumper $fields;
			rex_reply_simple undef, $rex, HTTP_OK,[], "files uploaded to disk";
	};

	define_route POST=> "/form_url"=> rex_save_form  sub {

		my $rex=$_[1];
		my $fields=$_[2];
		say "save form ",Dumper $fields;
			rex_reply_simple undef, $rex, HTTP_OK,[], "url form uploaded";
	};

	define_route "/cmd"=>sub {
		#form sub mission via GET
		my $kv=$_[1]->query;#rex_parse_query_params $_[1];
		#my $kv=rex_parse_query_params $_[1];
		#say $kv->%*;
		rex_reply_simple @_, HTTP_OK,[],"yarrrp";
	};

	#Login processing
	define_route "GET"=>qr{(/login)}=>sub {
		push @_, "/login.htmlt";
		&{static_file_from "data"};
	};
	define_route "POST"=>qr{(/login)}=>sub {

		&{rex_save_web_form sub {
			pop;			#last flag
			say Dumper pop;		#fields from form
			say Dumper @_;

			rex_reply_simple @_, HTTP_OK, [], "yarrrp";

		}}
	};

	#end login processing

	define_route "/template"=>sub {
		my $buf="";
		include "./templates/login.vpl", $templates, @_;
		rex_reply_simple @_, HTTP_OK,[],$buf;
	};

};

$server->run;
