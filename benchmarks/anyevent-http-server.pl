#!/usr/bin/env perl
use common::sense;

use FindBin;use lib "$FindBin::Bin/../blib/lib";

use uSAC::HTTP::Server;
use uSAC::HTTP::Code qw<:constants>;
use uSAC::HTTP::Method qw<:constants>;
use uSAC::HTTP::Header qw<:constants>;
use uSAC::HTTP::Rex;
use Hustle::Table;
use EV;

my $table=Hustle::Table->new;
$table->set_default(sub {
		my ($uri,$rex,$ref)=@_;

		@$ref=(HTTP_NOT_FOUND,"Go away");
});
$table->add(
	{
		matcher=>qr|^(?<root>/)$|,
		sub=>sub{
			my ($uri, $rex,$ref)=@_;
			given($rex->[uSAC::HTTP::Rex::method_]){
				when(HTTP_GET){
					#response is imidiate
					#process and reply
					#no need to swap out reader
					#say  "GET METHOD"
					my @rv=(HTTP_OK,"GOODasdf"); 
					
					@$ref=@rv;
					
				}
				when(HTTP_POST){
					#Validate headers: do we want to service this method on this uri?
					#request has body.
					@$ref=(HTTP_METHOD_NOT_ALLOWED, "No way man..");
					$rex->[uSAC::HTTP::Rex::session_]->drop();

					#push reader sessions stack

					#process request body
					#Renstate older reader
					#Send reply
					#
					#When 
				}
				when("UPDATE"){
				}
				when("DELETE"){
				}
				when("PUT"){
				}
				when("HEAD"){
				}
				default {
					#unkown method
					#respond as such.
				}

			}
			1;
		}
	},
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
