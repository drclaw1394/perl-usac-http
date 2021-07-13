#!/usr/bin/env perl
use common::sense;

use FindBin;use lib "$FindBin::Bin/../lib";
use EV;
use AnyEvent;

BEGIN {
	@uSAC::HTTP::Server::Subproducts=("testing/1.2");
}
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
		matcher=>qr|POST /urlencoded|ao,
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
#for normal get/head
# read all the headers
# test/build response
# #read remaining data on connection* (should be none)
# Send rely
#
#
# for post
# need to check if url exists
# if so read body
# then proces and generate reponse
# if uri not accessable need reply 404 and then close connection instaed of reading 

#####################################################################################################################################################
#                 my $req=$_[0];                                                                                                                    #
#                 given ($req->[0]){                                                                                                                #
#                         when ("GET"){                                                                                                             #
#                                 return (200,"GOOD");                                                                                              #
#                                                                                                                                                   #
#                         when ("POST"){                                                                                                            #
#                                 return (sub { print $_[1]->$*;print "Method $req->[0]"; $req->[3]->("HTTP/1.1 200 OK\nContent-Length: 0\n\n");}); #
#                         }                                                                                                                         #
#                                                                                                                                                   #
#                         when ("PUT"){                                                                                                             #
#                                                                                                                                                   #
#                         }                                                                                                                         #
#                                                                                                                                                   #
#                         default {                                                                                                                 #
#                         	#dynamic matching here
#                                 #pass through?                                                                                                    #
#                         }                                                                                                                         #
#                 }                                                                                                                                 #
#         }                                                                                                                                         #
# }                                                                                                                                                 #
#                                                                                                                                                   #
#                                                                                                                                                   #
# );                                                                                                                                                #
#                                                                                                                                                   #
#####################################################################################################################################################
$server->listen;
$server->accept;
EV::loop();
