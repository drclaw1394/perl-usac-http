#!/usr/bin/env perl
#
use EV;
use AnyEvent;

use Log::ger::Output 'Screen';

use uSAC::HTTP;
use uSAC::HTTP::Server;


use uSAC::HTTP::Middleware::Static;
use uSAC::HTTP::Middleware::Log;
use uSAC::HTTP::Middleware::Deflate;
use uSAC::HTTP::Middleware::Gzip;
use uSAC::HTTP::Middleware::Slurp;
use uSAC::HTTP::Middleware::Multipart;
use uSAC::HTTP::Middleware::ScriptWrap;
use uSAC::HTTP::Middleware::Redirect;
use uSAC::HTTP::Middleware::State;

#use HTTP::State ":all";

###########################################################
# use use::prefix ("uSAC::HTTP::",                        #
#   Static=>[], #default import                           #
#   Static=>Log  #Next item is a string, so defaul import #
#   Static=>["options"], #request particular imports      #
#   Static=>undef,  # no default import into namespace    #
#   Static=>[{}],                                         #
#   Log=>[{"asdf"=>","}]                                  #
#   Deflate Gzip Slurp Multipart ScripWrap Redirect State #
#   >;                                                    #
###########################################################

#use uSAC::HTTP::Middleware::State::JSON qw<state_json>;
#use uSAC::HTTP::Middleware::State::UUID qw<state_uuid>;
#

# Delegate has class subs for sets of middleware
#
#require(path(\"delegate.pl"));


my $server; $server=usac_server {
  usac_workers 4;
  usac_listen {
    address=>"::",
    interface=>["en"],
    port=>[8084],
    family=>["AF_INET6"],
    type=>"SOCK_STREAM",
    data=> {
            hosts=>"dfs"
    }
  };

	usac_sub_product "blog";
	
	usac_site {
    usac_id "blog";
    #usac_host "localhost:8084";

    usac_delegate \"delegate.pl";

    #usac_middleware uhm_log(dump_headers=>1);
    #usac_middleware $_ for uhm_log(dump_headers=>1), uhm_state, uhm_deflate;#uhm_gzip;#, uhm_deflate;

		#usac_route '/favicon.png$'   => usac_cached_file "images/favicon.png";
		#
  
    usac_route "/getme/($Comp)"
      =>sub {
        $_[PAYLOAD]=join ", ", &rex_captures->@*;
        1;
      };
    usac_route "/redirect"
      =>sub {
        $_[OUT_HEADER]{":status"}=301;
        $_[OUT_HEADER]{HTTP_LOCATION()}="http://localhost:8084/static/hot.txt";
      };

		usac_route '/static/hot.txt'
      ##############################
      # => sub {                   #
      #   say Dumper $_[IN_HEADER] #
      # }                          #
      #=> uhm_gzip()
      #=> uhm_deflate()
      #=>uhm_multipart()
      #=>uhm_log(dump_headers=>1)
     ######################################################
      ######################################################################
      # =>sub {                                                            #
      #   require Data::Dumper;                                            #
      #   say "MY state : ". Data::Dumper::Dumper $_[IN_HEADER]{":state"}; #
      #   1;                                                               #
      # }                                                                  #
      ######################################################################
      => uhm_static_file(
        #headers=>{"transfer-encoding"=>"chunked"}, 
        \"static/hot.txt");

    usac_route "/die"
      => sub {
        my $a=10/0;
        use Exception::Class::Base;
        Exception::Class::Base->throw("Did not want to live");
      };  

    usac_route "/no_write"
      => sub {
        $_[PAYLOAD]="no write indeed";
      };

    usac_route "/loopback"
      => sub {
        $_[PAYLOAD]="OK"
      };

    usac_route '/statictest$'
      => uhm_static_content "This is some data";

    usac_route "/static"
    #=> uhm_gzip()
      #=>uhm_deflate()
      => uhm_static_root (
            #filter=>'txt$',
            read_size=>4096*16,
            #pre_encoded=>{gzip=>".gz"},
            #no_compress=>qr/txt$/,
            do_dir=>1,
            #indexes=>["index.html"],
            #sendfile=>0,#4096*32,
            #\undef #"static/" 
            \undef
    );

    usac_include \"admin/usac.pl";

    usac_route GET
      =>"/wrapped"
      =>uhm_script_wrap() # Wrap result so usable as javascript source
      => sub {
        $_[PAYLOAD]=qq|
        <form method="post" action="/multipart">
          <input name="dummy" type="text" value="test value">
          <input type="submit">
        </form>|;
      };


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
      #=>uhm_multipart()
      =>uhm_slurp(
        close_on_complete=>1,
        #upload_dir=>"uploads" 
      )
      =>sub {
      #use Data::Dumper;
      #say "GOT PAYLOAD: ", Dumper $_[PAYLOAD];
        if(ref $_[PAYLOAD]){
          $_[PAYLOAD]=$_[PAYLOAD][0][1];
        }
        $_[OUT_HEADER]{HTTP_CONTENT_TYPE()}="text/plain" if $_[OUT_HEADER];

        1; #Auto call next
      };

    usac_route POST
      => "/stream_url_upload\$"
      => sub {
        say "Expecting, content, chunged, multipart or similar";
        #$_[PAYLOAD]=1Dumper $_[PAYLOAD];
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
        1;
		  };

		usac_error_page 404 
      => "/error";

		usac_error_page 415 
      => "/error";

    # Special route which is last in site to catch errors
    usac_catch_route uhm_error_not_found;
	};

  usac_run;
};
