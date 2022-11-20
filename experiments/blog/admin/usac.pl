use strict;
use warnings;
use feature ":all";

use Data::Dumper;
use uSAC::HTTP::Site;
use uSAC::HTTP::Server;
use uSAC::HTTP::Static;
use uSAC::HTTP::Middleware qw<log_simple>;
use Template::Plexsite::URLTable;
use Socket ":all";
use uSAC::HTTP::Rex;

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
		usac_error_route "/error/404" => sub {
			rex_write (@_, "An error occored: $_[2]");
		};

		usac_error_page 404 => "/error/404";
		usac_route "/static"   => usac_file_under usac_dirname;

		my $vars={fields=>[], peer=>undef};

		usac_route "/about" => sub {
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
			
			#Find out which address is us
			my $sockaddr=$_[1][uSAC::HTTP::Rex::peer_];
			(undef,$vars->{peer},undef)=getnameinfo $sockaddr, NI_NUMERICHOST;

			#say "PEER IP is $vars->{peer}";	
			#say "Family is ", sockaddr_family $sockaddr;
			#say "addr is", unpack_sockaddr_in6 $sockaddr;

			my $template=Template::Plex->immediate(undef,\*DATA,$vars);
			push @_, $template;
			push $_[3]->@*, HTTP_CONTENT_TYPE, "text/html";
			&rex_write
		};
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
