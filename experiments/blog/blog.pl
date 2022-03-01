#!/usr/bin/env perl
use uSAC::HTTP;
use uSAC::HTTP::Middleware qw<dummy_mw log_simple chunked deflate gzip>;


use uSAC::MIME;
use Data::Dumper;

my $server; $server=usac_server {
	usac_listen "127.0.0.1:8082";
	#usac_mime_db uSAC::MIME->new->rem("txt"=>"text/plain")->add("txt"=>"crazy/type");
	#usac_mime_default "some/stuff";
	#usac_listen "192.168.1.104";
	usac_sub_product "blog";
	#usac_middleware log_simple;
	my $site;$site=usac_site {
		usac_id "blog";
		usac_host "127.0.0.1:8082";
		usac_host "localhost:8082";

		#usac_middleware log_simple;

		usac_route "/favicon.png"   => usac_cached_file "images/favicon.png";
		usac_route "/static/hot.txt" =>	usac_cached_file "static/hot.txt";
		usac_route "/statictest"=> usac_static_content "This is some data";

		usac_route "testing.txt"=>deflate()=>sub {
				rex_write @_, HTTP_OK, [HTTP_CONTENT_TYPE, "text/plain"], "HELLO";
				#rex_write @_, HTTP_OK, [HTTP_CONTENT_LENGTH, 5], "HELLO";
		};

		usac_route "/static/$Dir_Path"=> usac_dir_under renderer=>"json", usac_path root=>usac_dirname, "static";

		usac_route "/static/$File_Path"   =>deflate()=>usac_file_under (
			#filter=>'mp4$',
			read_size=>4096*32, 
			#sendfile=>4096, 
			usac_path root=>usac_dirname, "static"
		);
                        ##################################################
                        # =>usac_file_under (                            #
                        #         usac_path root=>usac_dirname, "static" #
                        # );                                             #
                        # #################################              #
                        # # =>sub {                       #              #
                        # #         &rex_error_not_found; #              #
                        # # };                            #              #
                        # #################################              #
                        ##################################################
		
		usac_route "noreply"=>sub {

		};

		usac_route "test/$Comp/$Comp" => sub {
			my $q=&rex_query_params;
			rex_write @_, HTTP_OK, [], "Comp1 $1, Comp $2, query " . Dumper($q);
		};

		usac_route "test2/$File_Path" => sub {
			rex_write @_, HTTP_OK,[], "Comp2 $1";#, Comp $2";
		};

		usac_route "test3/$File_Path" => sub {
			my $q=&rex_query_params;
			#say Dumper rex_query_params $rex;
			rex_write @_, HTTP_OK, [], [$1, Dumper $q];	#"Test3 Comp3 $1, Comp ${\$rex->query_params}";
		};
		
                ###################################################################################
                # usac_route "file/$File_Path" => sub {                                           #
                #         state $static;                                                          #
                #         local $_=$_[0][4] and $static= usac_file_under "static" unless $static; #
                #                                                                                 #
                #         #test file                                                              #
                #         if($1 eq "test.txt"){                                                   #
                #                 push @_, "test.txt";                                            #
                #                 &$static;#->(@_, "test.txt");                                   #
                #         }                                                                       #
                #         else {                                                                  #
                #                 say "not found";                                                #
                #                 rex_reply_simple @_, HTTP_NOT_FOUND, [], "";                    #
                #         }                                                                       #
                # };                                                                              #
                ###################################################################################

		usac_include "admin/usac.pl";
	};


	#usac_route "/static/$Path" => static_file_from "static";
	
	#usac_route  "/static/$Path"=> static_file_from "static", cache_size=>10;
};
$server->run();
