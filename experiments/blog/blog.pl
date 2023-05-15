#!/usr/bin/env perl
use EV;
use AnyEvent;

use Log::ger::Output 'Screen';

use uSAC::HTTP;

use uSAC::HTTP::Middleware::Static;
use uSAC::HTTP::Middleware::Log;
use uSAC::HTTP::Middleware::Deflate;
use uSAC::HTTP::Middleware::Gzip;
use uSAC::HTTP::Middleware::Slurp;
use uSAC::HTTP::Middleware::Multipart;

#use uSAC::HTTP::Middleware::State::JSON qw<state_json>;
#use uSAC::HTTP::Middleware::State::UUID qw<state_uuid>;


use Socket;
use Net::ARP;
use uSAC::HTTP::Rex;



#use uSAC::MIME;
use Data::Dumper;

my $server; $server=usac_server {
  usac_workers 4;
  usac_listen {
    address=>"::",
    interface=>["en"],
    port=>[8084],
    family=>[AF_INET6],
    type=>SOCK_STREAM,
    data=> {
            hosts=>"dfs"
    }
  };


	

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
	usac_site {
    usac_id "blog";
    #usac_host "127.0.0.1:8084";
    #usac_host "localhost:8084";
    #usac_host "192.168.1.102:8084";


		#
		#usac_route '/favicon.png$'   => usac_cached_file "images/favicon.png";
		#
		
		#error route forces a get method to the resource
  
    usac_route "/getme/($Comp)"
      =>sub {
      #return unless $_[CODE];
        $_[PAYLOAD]=join ", ", &rex_captures->@*;
      };

		usac_route '/static/hot.txt'
      ##############################
      # => sub {                   #
      #   say Dumper $_[IN_HEADER] #
      # }                          #
      #=> uhm_gzip()
      #=> uhm_deflate()
      #=>uhm_multipart()
      => uhm_static_file headers=>{"transfer-encoding"=>"chunked"}, usac_path root=>usac_dirname, "static/hot.txt";

    usac_route "/die"
      => sub {
      #return unless $_[CODE];
      #say "a;lskjas;ldkjfa;lskjdf;lasjdf;lakjsdf;lakjsdf;lkajsdf;lkjasdfasf";
        my $a=10/0;
        use Exception::Class::Base;
        Exception::Class::Base->throw("Did not want to live");
      };  

    usac_route "/no_write"
      => uhm_gzip()
      => uhm_deflate()
      => sub {
        $_[PAYLOAD]="no write indeed";
      };

    usac_route "/loopback"
      => sub {
        $_[PAYLOAD]="OK"
      };

    usac_route '/statictest$'
      => uhm_static_content "This is some data";

                ##################################################################################################################
                # usac_route "/test/$Comp/$Comp" => sub {                                                                        #
                #         my $captures=&rex_captures;                                                                            #
                #         rex_write @_, $captures->[0];                                                                          #
                # };                                                                                                             #
                #                                                                                                                #
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
                usac_route "/static"
                #=> uhm_gzip()
                  #=>uhm_deflate()
                  => uhm_static_root (
                        #filter=>'txt$',
                        read_size=>4096*16,
                        pre_encoded=>{gzip=>".gz"},
                        #no_compress=>qr/txt$/,
                        do_dir=>1,
                        indexes=>["index.html"],
                        sendfile=>0,#4096*32,
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
    usac_route GET
      =>"/multipart"
      => sub {
        #render the form page
        use uSAC::HTTP::Route;
        $_[PAYLOAD]="some html goes gere";
        $_[OUT_HEADER]{HTTP_CONTENT_TYPE()}="text/plain";
        1;
      };

    usac_route POST
      =>"/multipart"

      =>uhm_multipart()
      =>uhm_slurp(
        close_on_complete=>1,
        upload_dir=>"uploads" 
      )
      =>sub {
        use Data::Dumper;
        #say Dumper $_[PAYLOAD];
        #say $_[PAYLOAD][0];
        say "GOT PAYLOAD: ", Dumper $_[PAYLOAD];
        if(ref $_[PAYLOAD]){
          $_[PAYLOAD]=$_[PAYLOAD][0][1];
        }
        $_[OUT_HEADER]{HTTP_CONTENT_TYPE()}="text/plain" if $_[OUT_HEADER];
        1;
      };

    usac_route POST
      => "/stream_url_upload\$"
      => sub {
        say "Expecting, content, chunged, multipart or similar";
        $_[PAYLOAD]=Dumper $_[PAYLOAD];
        1;
      };

    usac_route "GET"
      => "/stream_url_upload\$"
      => sub {
        &rex_error_unsupported_media_type;
      };

    usac_route POST
      => "/slurp_url_upload"
      =>uhm_slurp()
      => sub {
        say Dumper $_[PAYLOAD];
        $_[PAYLOAD]="OK";
        1;
      };

    usac_route POST
      => "/file_url_upload"
      #=> uhm_urlencoded_file(upload_dir=>usac_path(root=>usac_dirname, "uploads"))
      =>uhm_slurp()
      => sub {
      #return &rex_write unless $_[CODE];
      #NOTE: This is only called when all the data is uploaded
        say Dumper $_[PAYLOAD];
        $_[PAYLOAD]="OK";
        1;
      };

    usac_route POST
      => "/slurp_multi_upload"
      =>uhm_slurp()
      => sub {
        $_[PAYLOAD]="OK";
        1;
      };

    usac_route POST
      => "/file_multi_upload"
      #=> uhm_multipart_file(upload_dir=>usac_path(root=>usac_dirname, "uploads"))
      =>uhm_slurp()
      => sub {
        say Dumper $_[PAYLOAD];
        $_[PAYLOAD]="OK";
        1;
      };
    

    my %ctx;
    usac_route POST
      => "/stream_multi_upload\$"
      => sub {
      #return &rex_write unless $_[CODE];
        say "============";
        say "Expecting multipart";

        #Here we need to test if the headers of incomming parts have changed.

        my $ctx=$ctx{$_[REX]}//=0;
        $ctx+= length $_[PAYLOAD][1];
        $_[PAYLOAD]="DONE: $ctx";#. Dumper $_[PAYLOAD][0];
        say $ctx;
        delete $ctx{$_[REX]} unless($_[CB]);
      };
		

    #usac_route POST=>"/data_slurp" => MyApp::data_slurp;

    #usac_route "POST|GET"=>"/url_sl(.)rp\\?([^=]+)=(.*)" => MyApp::url_slurp;

    usac_error_route "/error" 
      => sub {
        $_[PAYLOAD]="CUSTOM ERROR PAGE CONTENT: ". $_[OUT_HEADER]{":status"};
        &rex_write;
		  };

		usac_error_page 404 
      => "/error";

		usac_error_page 415 
      => "/error";

		usac_catch_route usac_error_not_found;
	};


	#usac_route "/static/$Path" => static_file_from "static";
	
	#usac_route  "/static/$Path"=> static_file_from "static", cache_size=>10;
  usac_run;
};
#$server->run();
