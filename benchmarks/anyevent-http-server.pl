#!/usr/bin/env perl

use FindBin;use lib "$FindBin::Bin/../blib/lib";
use AnyEvent::HTTP::Server;
use EV;
use feature "switch";
use HTTP::Codes;

my $server = AnyEvent::HTTP::Server->new(
	host=>"0.0.0.0",
	port=>8080,
	cb => sub {
		(HTTP::Codes::OK,"GOOD");#[HTTP::Headers::Cache_Control=>"abc"],{Custom=>"value"});
	}
);

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
