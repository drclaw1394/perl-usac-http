#!/usr/bin/env perl
#use Log::ger::Util;
BEGIN{
	$ENV{LIBEV_FLAGS}=1; #POLL
}
use EV;
use AnyEvent;



use uSAC::HTTP;
use uSAC::HTTP::Middleware qw<dummy_mw log_simple deflate gzip>;

use uSAC::HTTP::State::JSON qw<state_json>;
use uSAC::HTTP::State::UUID qw<state_uuid>;
use Socket ":all";
use Net::ARP;

use MyApp;
use Log::ger::Output 'Screen';




#use uSAC::MIME;
use Data::Dumper;

my $server; $server=usac_server {;

	usac_listen( {
			address=>"::",
			interface=>["en"],
			port=>[8084],
			family=>[AF_INET6],
			type=>SOCK_STREAM,
			data=> {
				hosts=>"dfs"
			}
		}
	);


	

	#usac_mime_db uSAC::MIME->new->rem("txt"=>"text/plain")->add("txt"=>"crazy/type");
	#usac_mime_default "some/stuff";
	#usac_listen "192.168.1.104";
	
	#usac_error_route "/error/404" => sub {
	#		rex_write (@_, "An error occored: $_[2]");
	#	};

		#usac_error_page 404 => "/error/404";
	usac_sub_product "blog";
  #usac_middleware log_simple dump_headers=>1;
	
  #usac_middleware log_simple dump_headers=>1;
	my $site; $site=usac_site {
		usac_id "blog";
		usac_host "127.0.0.1:8082";
		usac_host "localhost:8084";
		usac_host "192.168.1.102:8084";


		#
		#usac_route '/favicon.png$'   => usac_cached_file "images/favicon.png";
		#
		
		#error route forces a get method to the resource

		usac_route '/static/hot.txt' =>	gzip()=>deflate()=>usac_cached_file headers=>[unkown=>"A"], usac_path root=>usac_dirname, "static/hot.txt";


                ##################################################################################################################
                # usac_route "/test/$Comp/$Comp" => sub {                                                                        #
                #         my $captures=&rex_captures;                                                                            #
                #         rex_write @_, $captures->[0];                                                                          #
                # };                                                                                                             #
                #                                                                                                                #
                # usac_route '/statictest$'=> usac_static_content "This is some data";                                           #
                #                                                                                                                #
                # usac_route 'testing.txt'=>state_json()=>state_uuid()=>deflate()=>sub {                                         #
                #         my $state=&rex_state;                                                                                  #
                #         say "Existing state: ". $state->{json}{id};                                                            #
                #         say "Existing state: ". $state->{uuid};                                                                #
                #         $state->{json}{id}="HELLO".rand 10;                                                                    #
                #         $state->{uuid}="HELLO".rand 10;                                                                        #
                #         push $_[3]->@*, HTTP_CONTENT_TYPE, "text/plain";                                                       #
                #         rex_write @_, "HELLO";                                                                                 #
                # };                                                                                                             #
                #                                                                                                                #
                # #                                                                                                            # #
                # # #usac_route "/static/$Dir_Path"=> usac_dir_under renderer=>"json", usac_path root=>usac_dirname, "static"; # #
                # #                                                                                                            # #
                usac_route "/static"=>
                gzip()=>deflate()=>
                usac_file_under (
                        #filter=>'txt$',
                        read_size=>4096,
                        #pre_encoded=>[qw<gz>],
                        #no_compress=>qr/txt$/,
                        do_dir=>1,
                        #indexes=>["index.html"],
                        #sendfile=>4096,
                        usac_dirname #  "static"
                );

                usac_include usac_path root=>usac_dirname, "admin/usac.pl";                                                    #
                ##################################################################################################################

                ##############################################
                # => usac_file_under (                       #
                #         do_dir=>1,                         #
                #         read_size=>4096*32,                #
                #         no_compress=>'jpg$',               #
                #         #sendfile=>12,                     #
                #         usac_path root =>usac_dirname, "." #
                # );                                         #
                ##############################################

    usac_route POST=>"/new_data\$"=>sub {
        say "Expecting, content, chunged, multipart or similar";
        #say "Payload: $_[PAYLOAD]";
        $_[PAYLOAD]=Dumper $_[PAYLOAD];
        &rex_write;
    };

    my %ctx;
    usac_route POST=>"/new_data_multi\$"=>sub {
        say "============";
        say "Expecting multipart";
        say $_[REX];
        #say "args: ".join ", ", @_;
        my $ctx=$ctx{$_[REX]}//=0;
        $ctx+= length $_[PAYLOAD][1];
        $_[PAYLOAD]="DONE: $ctx";#. Dumper $_[PAYLOAD][0];
        say $_[PAYLOAD];
        delete $ctx{$_[REX]} unless($_[CB]);
        &rex_write;
    };
		
		usac_route POST=>"/upload\$"=>usac_data_stream
		sub {
			my $cb=sub {say "CALLBACK";};
			sub {
				say join ", ", @_;
				say "STREAMING DATA";
				$_[CB]&&=$cb;
				&rex_write;
			}
		};

		usac_route POST=>"/upload2"=>usac_urlencoded_stream sub {
			sub {
				$_[CB]=undef;
				&rex_write;
			}
		};

		usac_route POST=>"/upload3"=>usac_multipart_stream sub {
			my $cb=sub {say "CALLBACK multipart";};
			my $prev=0;
			sub {
				if($prev != $_[CB]){
					say "NEW SECTION====";
					$prev=$_[CB];
				}
				say "in multipart handler";
				$_[CB]&&=$cb;
				&rex_write;

			}
		};

		usac_route POST=>"/form_stream"=>usac_form_stream sub {
			say "======;lka;k;lkasdfasdf";
			my $cb=sub {say "CALLBACK FROM STREAM";};
			my $prev=0;
			sub {
				if($prev != $_[CB]){
					say "NEW SECTION====";
					$prev=$_[CB];
				}
				say "in multipart handler";
				$_[CB]&&=$cb;
				&rex_write;

			}
		};

		#usac_route POST=>"/data_slurp" => usac_data_slurp sub {
		usac_route POST=>"/data_slurp" => MyApp::data_slurp;
                ###############################################################
                # usac_data_slurp sub {                                       #
                #         say "data Slurp route";                             #
                #         say join ", ", @_;                                  #
                #         $_[PAYLOAD]="GOT DATA";                             #
                #         say Dumper $_[CB];                                  #
                #         $_[CB]=undef;#&&=sub { say "DATA SLURP CALLBACK";}; #
                #         &rex_write;                                         #
                #                                                             #
                # };                                                          #
                ###############################################################

		#usac_route "POST|GET"=>"/url_sl(.)rp\\?([^=]+)=(.*)" => usac_urlencoded_slurp sub {
		usac_route "POST|GET"=>"/url_sl(.)rp\\?([^=]+)=(.*)" => MyApp::url_slurp;
                #########################################################
                # usac_urlencoded_slurp sub {                           #
                #         say "URL encoded Slurp route";                #
                #         say Dumper $_[REX]->query_params;             #
                #         say "CAPTURES: ".Dumper &rex_captures;        #
                #         say join ", ", @_;                            #
                #         @_[PAYLOAD, CB]=(Dumper($_[PAYLOAD]), undef); #
                #         &rex_write;                                   #
                #                                                       #
                # };                                                    #
                #########################################################

		usac_route POST=>"/multi_slurp"=>usac_multipart_slurp sub {
			say "multipart Slurp route";
			say join ", ", @_;
			$_[PAYLOAD]="GOT DATA";
			say Dumper $_[CB];
			$_[CB]=undef;#&&=sub { say "DATA SLURP CALLBACK";};
			&rex_write;
			
		};

                # usac_route "noreply"=>sub {                                                                                #
                #                                                                                                            #
                # };                                                                                                         #
                #                                                                                                            #
                # usac_route "test/$Comp/$Comp" => sub {                                                                     #
                #         my $q=&rex_query_params;                                                                           #
                #         rex_write @_, HTTP_OK, [], "Comp1 $1, Comp $2, query " . Dumper($q);                               #
                # };                                                                                                         #
                #                                                                                                            #
                # usac_route "test2/$File_Path" => sub {                                                                     #
                #         rex_write @_, HTTP_OK,[], "Comp2 $1";#, Comp $2";                                                  #
                # };                                                                                                         #
                #                                                                                                            #
                # usac_route "test3/$File_Path" => sub {                                                                     #
                #         my $q=&rex_query_params;                                                                           #
                #         #say Dumper rex_query_params $rex;                                                                 #
                #         rex_write @_, HTTP_OK, [], [$1, Dumper $q];     #"Test3 Comp3 $1, Comp ${\$rex->query_params}";    #
                # };                                                                                                         #
                #                                                                                                            #
                # ###################################################################################                        #
                # # usac_route "file/$File_Path" => sub {                                           #                        #
                # #         state $static;                                                          #                        #
                # #         local $_=$_[0][4] and $static= usac_file_under "static" unless $static; #                        #
                # #                                                                                 #                        #
                # #         #test file                                                              #                        #
                # #         if($1 eq "test.txt"){                                                   #                        #
                # #                 push @_, "test.txt";                                            #                        #
                # #                 &$static;#->(@_, "test.txt");                                   #                        #
                # #         }                                                                       #                        #
                # #         else {                                                                  #                        #
                # #                 say "not found";                                                #                        #
                # #                 rex_reply_simple @_, HTTP_NOT_FOUND, [], "";                    #                        #
                # #         }                                                                       #                        #
                # # };                                                                              #                        #
                # ###################################################################################                        #
                #                                                                                                            #
		#
		#usac_include "admin/usac.pl";                                                                             #
	       	usac_error_route "/error/404" => sub {
				say "ERROR FOR BLOG";
				$_[PAYLOAD]="CUSTOM ERROR PAGE CONTENT: ".$_[CODE];
				&rex_write;
		};

		usac_error_page 404 => "/error/404";
		usac_catch_route usac_error_not_found;
	};


	#usac_route "/static/$Path" => static_file_from "static";
	
	#usac_route  "/static/$Path"=> static_file_from "static", cache_size=>10;
};
$server->run();
