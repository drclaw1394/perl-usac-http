#!/usr/bin/env perl
use common::sense;

use FindBin;use lib "$FindBin::Bin/../lib";
use EV;
use AnyEvent;

BEGIN {
	@uSAC::HTTP::Server::Subproducts=("testing/1.2");
}
my $fork=0;
my @sys_roots=qw<data>;
use uSAC::HTTP::Server;

use uSAC::HTTP::Code qw<:constants>;
use uSAC::HTTP::Method qw<:constants>;
use uSAC::HTTP::Header qw<:constants>;
use uSAC::HTTP::Rex;
use uSAC::HTTP::v1_1_Reader;
use uSAC::HTTP::Static;
use Hustle::Table;

use constant {
	HTTP_1_0=>"HTTP/1.0",
	HTTP_1_1=>"HTTP/1.1",
};

use constant LF=>"\015\012";

our $ANY_METH=qr/^(?:GET|POST|HEAD|PUT|UPDATE|DELETE) /;
our $ANY_URL=qr/.*+ /;
our $ANY_VERS=qr/HTTP.*$/;

sub begins_with {
	my $test=$_[0];
	sub{0 <= index $_[0], $test},
}

sub matches_with {
	return qr{$_[0]}oa;
}

sub ends_with {
	my $test=reverse $_[0];
	sub {0 <= index reverse($_[0]), $test}
}


my $table=Hustle::Table->new;

$table->set_default(sub {
		my ($line,$rex)=@_;
		uSAC::HTTP::Rex::reply_simple $rex, (HTTP_NOT_FOUND,"Go away: $rex->[uSAC::HTTP::Rex::method_]");
});

$table->add(
	{
		matcher=>qr{GET /data/(.*) }ao,
		sub=>sub {
			my ($line, $rex)=@_;
			my @headers;
			#say "STATIC FILE server";
			#look for static files in nominated static directories	
			send_file_uri $rex, $1, "data";
			return;		
		}
	},

	{
		#matcher=>"GET / HTTP/1.0",
		matcher=>matches_with("GET /"),
		sub=>sub{
			my ($line, $rex)=@_;
			uSAC::HTTP::Rex::reply_simple $rex, (HTTP_OK,"a" x 1024);
			return;	#enable caching for this match
		}
	},

	{
			   #POST /urlencoded HTTP/1.1
		matcher=>qr{POST /urlencoded HTTP/1[.]1}ao,
		sub=>sub {
			my ($line, $rex)=@_;
			my $session=$rex->[uSAC::HTTP::Rex::session_];
			say "POST ENDPOINT";


			$session->push_reader(
				"http1_1_urlencoded",
				sub {
					if(defined $_[0]){
						#say "GOT POST DATA $_[0]";
					}
					else{
						#say "END OF POST PROCESSING";
						#$rex->reply_simple(HTTP_OK,"finished post"); 
						uSAC::HTTP::Rex::reply_simple $rex, (HTTP_OK,"finished post");
					}
					#the callback to handle the posted data
				},
				#remaining options ref for the reader? eg write to file?
			);
			#check for expects header and send 100 before trying to read
			given($rex->[uSAC::HTTP::Rex::headers_]){
				if(defined($_->{expects})){
					#issue a continue response	
					my $reply= "HTTP/1.1 ".HTTP_CONTINUE.LF.LF;
					$rex->[uSAC::HTTP::Rex::write_]->($reply);
				}
			}
			$session->[uSAC::HTTP::Server::Session::read_]->(\$session->[uSAC::HTTP::Server::Session::rbuf_],$rex,
			);
			return;
		}
	},
	{
		matcher=>begins_with("POST /formdata"),
		sub=>sub {
			say "FORM DATA ENDPOINT";
			my ($line,$rex)=@_;
			my $session=$rex->[uSAC::HTTP::Rex::session_];
			$session->push_reader(
				#\&make_form_data_reader,
				"http1_1_form_data",
				sub {

					say "+_+_+_+FORM CALLBACK";
					say "DATA:", $_[0];
					#need to encode the state? diff parts
					#	ie with undef data and just headers => new part
					#	with undef headers and data	=> part continues
					#	with undef header and undef data => form end
					#Parts are in sequence
					unless (defined $_[0] and defined $_[1]){
						uSAC::HTTP::Rex::reply_simple $rex, (HTTP_OK,"finished multipart form");
					}
				}
			);
			$session->[uSAC::HTTP::Server::Session::read_]->(\$session->[uSAC::HTTP::Server::Session::rbuf_],$rex);
			return;
		}
	},
	#############################
	# when("UPDATE"){           #
	# }                         #
	# when("DELETE"){           #
	# }                         #
	# when("PUT"){              #
	# }                         #
	# when("HEAD"){             #
	# }                         #
	# default {                 #
	#         #unkown method    #
	#         #respond as such. #
	# }                         #
	#############################

	{
		matcher=>"/test",
		sub=>sub{
			say " THIS IS A  TEST\n";
		}
	},

);
my $dispatcher=$table->prepare_dispatcher;

$dispatcher->("/test");

my $server = uSAC::HTTP::Server->new(
	host=>"0.0.0.0",
	port=>8080,
	cb=>$dispatcher
);

$server->listen;
if($fork){
	for (1..3) {
		my $pid = fork();
		if ($pid) {
			next;
		} else {
			last;
		}
	}
}
$server->accept;
EV::loop();
