#!/usr/bin/env perl

use FindBin;use lib "$FindBin::Bin/../blib/lib";

use uSAC::HTTP::Server;
use uSAC::HTTP::Code;
use uSAC::HTTP::Rex;
use Hustle::Table;
use EV;
use feature "switch";

my $table=Hustle::Table->new;

$table->set_default(sub{
		#return a 404 error
	});
$table->add(
	{
		matcher=>"/",
		sub=>sub{
			my $uri=shift;
			my $rex=shift;
			my $ref=shift;
			my @rv=(uSAC::HTTP::Code::HTTP_CODE_OK,"GOOD"); 
			
			@$ref=@rv;
			1;
		}
	},
	{
		matcher=>"/test",
		sub=>sub{
			print " THIS IS A  TEST\n";
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
