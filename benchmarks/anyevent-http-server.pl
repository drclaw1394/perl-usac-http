#!/usr/bin/env perl
use common::sense;
use feature "refaliasing";
no warnings "experimental";
use Data::Dumper;
	my $fork=$ARGV[0]//0;
BEGIN {
	@uSAC::HTTP::Server::Subproducts=("testing/1.2");
}

use FindBin;use lib "$FindBin::Bin/../lib";
use EV;
say EV::backend;
use AnyEvent;

my @sys_roots=qw<data>;
use uSAC::HTTP::Server;

use uSAC::HTTP::Code qw<:constants>;
use uSAC::HTTP::Method qw<:constants>;
use uSAC::HTTP::Header qw<:constants>;
use uSAC::HTTP::Rex;
use uSAC::HTTP::Cookie qw<:constants>;
use uSAC::HTTP::v1_1_Reader;
use uSAC::HTTP::Static;
use uSAC::HTTP::Server::WS;
use Hustle::Table;


use constant LF=>"\015\012";

given(\%uSAC::HTTP::Server::Session::make_writer_reg){
	$_->{http1_1_static_writer}=\&make_static_file_writer;
}

our $ANY_METH=qr/^(?:GET|POST|HEAD|PUT|UPDATE|DELETE) /;
our $ANY_URL=qr/.*+ /;
our $ANY_VERS=qr/HTTP.*$/;

my $any_method=		qr{^([^ ]+)}ao;
my $path=		qr{([^? ]+)}ao;
my $comp=		qr{([^/ ]+)}ao;
my $query=		qr{(?:[?]([^# ]+)?)?}ao;
my $fragment=		qr{(?:[#]([^ ]+)?)?}ao;

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
		say "DEFAULT: $line";
		push @_, (HTTP_NOT_FOUND,undef,"Go away: $rex->[uSAC::HTTP::Rex::method_]");
		&uSAC::HTTP::Rex::reply_simple;#h $rex, ;
});

$table->add(qr{^GET /login}ao => sub {
		#set a cookie
		my @cookies=(
			uSAC::HTTP::Cookie->new(
				test=>"value",
				COOKIE_EXPIRES, time+60
			),
			uSAC::HTTP::Cookie->new(
				another=>"valucawljksdfe",
				COOKIE_MAX_AGE,1000
			),
		);


		push @_, (HTTP_OK,
			[map {(HTTP_SET_COOKIE,$_->serialize_set)} @cookies #cookies
			],
			"HELLO");

		&uSAC::HTTP::Rex::reply_simple;
	}
);

##################################################################################################
# $table->add("GET /data/index.html HTTP/1.1"=> sub {                                            #
#                 #\my $line=\$_[0];                                                             #
#                 #\my $rex=\$_[1];                                                              #
#                 #parse cookie                                                                  #
#                 #                                                                              #
#                 #my $cookies;                                                                  #
#                                                                                                #
#                 #$cookies=uSAC::HTTP::Cookie::parse $rex->[uSAC::HTTP::Rex::headers_]{cookie}; #
#                                                                                                #
#                                                                                                #
#                 #say Dumper $cookies;                                                          #
#                 push @_,"index.html","data";                                                   #
#                 &send_file_uri_norange;                                                        #
#                 return;                                                                        #
#         }                                                                                      #
# );                                                                                             #
##################################################################################################
#
$table->add(qr{^GET /data/$path}ao=> sub {
		#\my $line=\$_[0];
		#\my $rex=\$_[1];
		#parse cookie
		#
		#my $cookies;

		#$cookies=uSAC::HTTP::Cookie::parse $rex->[uSAC::HTTP::Rex::headers_]{cookie};


		#say Dumper $cookies;
		push @_,$1,"data";
		&send_file_uri_norange;
		return;		
	}
);

$table->add(qr<GET /ws>=>sub {
		#create a web socket here
		#once created, the callback is called with the ws object	

		#check the headers if this is allowed
		#$_->{'sec-webSocket-protocol'} =~ /.*/  #sub proto
		#

		#Then do the handshake or error otherwise
		#
		push @_,"/ws", sub {
			my $ws=shift;
			say "Got websocket";

		};
		&upgrade_to_websocket;

	}
);

$table->add(qr{^GET /}ao => sub{
		#my ($line, $rex)=@_;
		#\my $line=\$_[0];
		#\my $rex=\$_[1];
		#headers todo:
		#
		#parse cookies?
		my $data="a" x 1024;
		push @_, HTTP_OK,undef, $data;
		&uSAC::HTTP::Rex::reply_simple;
		return;	
	}
);

$table->add(qr{^POST /urlencoded}ao=>sub {
		my ($line,$rex)=@_;
		#my $rex=$_[1];
		#Check permissions, sizes etc?
		push @_, sub {
			uSAC::HTTP::Rex::reply_simple $line, $rex, HTTP_OK,undef,"finished post" unless defined $_[0];
		};

		&uSAC::HTTP::Rex::handle_upload;
		return;
	}
);

$table->add( begins_with("POST /formdata")=>sub {
			say "FORM DATA ENDPOINT";
			my ($line,$rex)=@_;
			push @_, sub {
				say "+_+_+_+FORM CALLBACK";
				say "DATA:", $_[0], " ";
				say $_[1]->%*;
				#need to encode the state? diff parts
				#	ie with undef data and just headers => new part
				#	with undef headers and data	=> part continues
				#	with undef header and undef data => form end
				#Parts are in sequence
				#
				#When no data or headers, we reached the end
				unless (defined $_[0] and defined $_[1]){
					uSAC::HTTP::Rex::reply_simple $line, $rex, HTTP_OK,"finished multipart form";
				}
			};

			&uSAC::HTTP::Rex::handle_form_upload;
			return;
		}
);


my $dispatcher=$table->prepare_dispatcher(type=>"online",cache=>{});

my $server = uSAC::HTTP::Server->new(
	host=>"0.0.0.0",
	port=>8080,
	cb=>$dispatcher
);


$server->listen;
	for (1..$fork-1) {
		my $pid = fork();
		if ($pid) {
			next;
		} else {
			last;
		}
	}
$server->accept;
EV::loop();
