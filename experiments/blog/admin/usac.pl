use strict;
use warnings;
use feature "say";

use uSAC::HTTP;
use uSAC::HTTP::Site;
#use uSAC::HTTP::Server;
use uSAC::HTTP::Middleware::Static;
use uSAC::HTTP::Middleware::Log;
use uSAC::HTTP::Middleware::Redirect;
use uSAC::Util;

use Template::Plexsite::URLTable;

use Socket qw<getnameinfo NI_NUMERICHOST>;# ":all";

use uSAC::HTTP::Rex;
use Sort::Key::Multi qw<sskeysort>;


say "ADMIN SETUP";
my $URLTable=Template::Plexsite::URLTable->new(src=>"src", html_root=>"static/build");
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
		#
		#error route forces a get method to the resource
		usac_route "/static"   => uhm_static_root \"";

		my $vars={
      fields=>[],
      peer=>undef
    };

		usac_route "/about" => sub {
			#Model
			#######
			my @data=`arp -an`;
			$vars->{fields}->@*=map {
				my %out;
				@out{qw<ip mac if>}=/((?:\d+\.){3}\d+)\)\s+at\s+((?:[0-9a-fA-F]+:){5}[0-9a-fA-F]+)\s+on\s+(\S+)/;
				\%out;
			} @data;

			@data=`ndp -na`;

			shift @data; #remove header
			push $vars->{fields}->@*, map {
				my %out;
				@out{qw<ip mac if>}=split /\s+/;
				\%out;
			} @data;
			
			#Controller
			#######
			$vars->{fields}->@*=sskeysort {$_->{mac},$_->{if}} $vars->{fields}->@*;
			#Find out which address is us
			my $sockaddr=$_[REX][uSAC::HTTP::Rex::peer_];
			(undef, $vars->{peer}, undef)=getnameinfo $sockaddr, NI_NUMERICHOST;

			#View/render
			###########
			$_[PAYLOAD]=Template::Plex->immediate(undef,\*DATA,$vars);
			$_[OUT_HEADER]{HTTP_CONTENT_TYPE()}= "text/html";
      1;
			&rex_write;
		};

		usac_error_route "/error/404" => sub {
			say "ERROR FOR BLOG admin";
      #$_[PAYLOAD]="CUSTOM ERROR PAGE CONTENT admin: $_[OUT_HEADER]{":status"}";
			&rex_write;
		};

		#usac_error_page uses the current site prefix
		usac_error_page 404 => "/error/404";

		#Catch all
    usac_catch_route uhm_error_not_found;
	};
	#usac_route "/static/$Path" => static_file_from "static";
	
	#usac_route  "/static/$Path"=> static_file_from "static", cache_size=>10;
};
1;
__DATA__
@{[ init {
	use Time::HiRes qw<time>;
	use feature ":all";
	
	#output location=>"admin", name=>"template";
}
]}

<table>
<tr><th>MAC</th><th>IP</th><th>IF</th></tr>
@{[jmap {"<tr><td>$_->{mac}</td><td>$_->{ip}</td><td>$_->{if}</td><td>". ($peer eq $_->{ip}?"CLIENT":"") ."</td></tr>"} "\n", @$fields]}
</table>
