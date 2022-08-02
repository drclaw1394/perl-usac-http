#!/usr/bin/env perl
use Log::ger::Output 'Screen';
use Log::ger::Util;

use Log::OK {
		lvl=>"warn",
		opt=>'verbose',

};

Log::ger::Util::set_level Log::OK::LEVEL;
use EV;
use uSAC::HTTP;
use uSAC::HTTP::Middleware qw<dummy_mw log_simple chunked deflate gzip>;






#use uSAC::MIME;
use Data::Dumper;

my $server; $server=usac_server {
	usac_listen no_hosts=>1, ["127.0.0.1:8084", "[::1]:8084"];
	#usac_listen "[::1]:8082";
	#usac_mime_db uSAC::MIME->new->rem("txt"=>"text/plain")->add("txt"=>"crazy/type");
	#usac_mime_default "some/stuff";
	#usac_listen "192.168.1.104";
	usac_sub_product "blog";
	#usac_middleware log_simple dump_headers=>1;
	my $site; $site=usac_site {
		usac_id "blog";
		#usac_host "127.0.0.1:8082";
		#usac_host "localhost:8082";

		#usac_middleware log_simple;
		#
		#usac_route '/favicon.png$'   => usac_cached_file "images/favicon.png";
		#
		
		#error route forces a get method to the resource
		usac_error_route "/error/404" => sub {
			rex_write (@_, "An error occored: $_[2]");
		};

		usac_error_page 404 => "/error/404";

		usac_route '/static/hot.txt' =>	gzip()=>deflate()=>usac_cached_file headers=>[unkown=>"A"], usac_path root=>usac_dirname, "static/hot.txt";

		usac_route "/test/$Comp/$Comp" => sub {
			my $captures=&rex_captures;
			rex_write @_, $captures->[0];
		};

                usac_route '/statictest$'=> usac_static_content "This is some data";

                usac_route 'testing.txt'=>deflate()=>sub {
			push $_[3]->@*, HTTP_CONTENT_TYPE, "text/plain";
                        rex_write @_, "HELLO";
                };
                #                                                                                                            #
                # #usac_route "/static/$Dir_Path"=> usac_dir_under renderer=>"json", usac_path root=>usac_dirname, "static"; #
                #                                                                                                            #
                usac_route "/static"=>gzip()=>deflate()=>usac_file_under (
			#filter=>'txt$',
                        read_size=>4096,
			#pre_encoded=>[qw<gz>],
			#no_compress=>qr/txt$/,
                        do_dir=>1,
                        indexes=>["index.html"],
                        #sendfile=>4096,
                        usac_dirname #  "static"
                );

                ##############################################
                # => usac_file_under (                       #
                #         do_dir=>1,                         #
                #         read_size=>4096*32,                #
                #         no_compress=>'jpg$',               #
                #         #sendfile=>12,                     #
                #         usac_path root =>usac_dirname, "." #
                # );                                         #
                ##############################################
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
                # #usac_include "admin/usac.pl";                                                                             #
                ##############################################################################################################
	};


	#usac_route "/static/$Path" => static_file_from "static";
	
	#usac_route  "/static/$Path"=> static_file_from "static", cache_size=>10;
};
$server->run();
