use strict;
use warnings;
use feature ":all";

use Data::Dumper;
use uSAC::HTTP;
use uSAC::HTTP::Server;
use uSAC::HTTP::Static;
use uSAC::HTTP::Middleware qw<log_simple>;

say "ADMIN SETUP";
my $server; $server=usac_server {

	#usac_port 8080;
	#usac_hosts 0;
	#usac_interface "0.0.0.0";
	usac_sub_product "blogadmin";
	#usac_innerware log_simple;

	usac_site {
		usac_id "admin";
		usac_prefix "/admin";
		#usac_host "127.0.0.1:8080";
		#usac_host "localhost:8080";
		#usac_innerware log_simple;
		usac_route "/static$Path"   => usac_static_from "static";
	};

	#usac_route "/static/$Path" => static_file_from "static";
	
	#usac_route  "/static/$Path"=> static_file_from "static", cache_size=>10;
};
#say Dumper $server;
$server->run();
