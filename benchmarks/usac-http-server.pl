#!/usr/bin/env perl
use common::sense;
use feature "refaliasing";
no warnings "experimental";
no feature "indirect";

use Data::Dumper;
	my $fork=$ARGV[0]//0;
BEGIN {
	@uSAC::HTTP::Server::Subproducts=("testing/1.2");
}

use AnyEvent;

use uSAC::HTTP::Server;

use uSAC::HTTP::Code qw<:constants>;
use uSAC::HTTP::Method qw<:constants>;
use uSAC::HTTP::Header qw<:constants>;
use uSAC::HTTP::Rex;
use uSAC::HTTP::Cookie qw<:all>;
use uSAC::HTTP::v1_1_Reader;
use uSAC::HTTP::Static;
use uSAC::HTTP::Server::WS;
use Hustle::Table;
use uSAC::HTTP::Middler;
use uSAC::HTTP::Middleware ":all";#qw<log_simple authenticate_simple>;

my $cv=AE::cv;

use constant LF=>"\015\012";

given(\%uSAC::HTTP::Session::make_writer_reg){
	$_->{http1_1_static_writer}=\&make_static_file_writer;
	$_->{http1_1_chunked_writer}=\&make_chunked_writer;
}
say "Chunked writer",\&make_chunked_writer;

our $ANY_METH=qr/^(?:GET|POST|HEAD|PUT|UPDATE|DELETE) /;
our $ANY_URL=qr/.*+ /;
our $ANY_VERS=qr/HTTP.*$/;

my $any_method=		qr{^([^ ]+)}o;
my $path=		qr{([^? ]+)}o;
my $comp=		qr{([^/ ]+)}o;
my $query=		qr{(?:[?]([^# ]+)?)?}o;
my $fragment=		qr{(?:[#]([^ ]+)?)?}o;

sub begins_with {
	my $test=$_[0];
	sub{0 <= index $_[0], $test},
}

sub matches_with {
	return qr{$_[0]}o;
}

sub ends_with {
	my $test=reverse $_[0];
	sub {0 <= index reverse($_[0]), $test}
}

my @sys_roots=qw<data>;
uSAC::HTTP::Static::enable_cache;




#restricted area. requests must be checked against session information
my $public_table=Hustle::Table->new(\&default_handler);

my $private_table=Hustle::Table->new(\&default_handler);

#Restricted area (username/password required)
$private_table->add(qr{GET /user/restricted}o => sub {
		\my $line=\$_[0];
		my $rex=$_[1];
		#return unless &$authorised;

		push @_, HTTP_OK, undef, "premission granted";
		&rex_reply_simple;


	}
);
$private_table->add(qr{^GET /user/logout}o=>sub{
		#send expiry on all known cookies of intrest
		#return unless &$authorised;
		say "doing logout";
		my @cookies=expire_cookies qw<test another>;
		$_->[COOKIE_PATH]="/" for @cookies;

		#add response, headers, body  and send it
		push @_, (HTTP_OK,	#this should be a  redirect to a login/ landing page?
			[map {(HTTP_SET_COOKIE,$_->serialize_set_cookie)} @cookies #cookies
			],
			"LOGOUT OK");

		&rex_reply_simple;
	}
);

#Public - No access restrictions

#This is the post handler for a form?
$public_table->add(qr{^GET /login}o => sub {
		#set a cookie
		my @cookies=(
			new_cookie( test=>"value",	 	COOKIE_EXPIRES, time+60),
			new_cookie( another=>"valucawljksdfe",	COOKIE_MAX_AGE, 1000),
		);

		#add response, headers, body  and send it
		push @_, (HTTP_OK,
			[map {(HTTP_SET_COOKIE,$_->serialize_set_cookie)} @cookies #cookies
			],
			"LOGIN OK");

		&rex_reply_simple;
	}
);

$public_table->add(qr{^GET /data/$path}o=> sub {
		#\my $line=\$_[0];
		\my $rex=\$_[1];

		my $cookies=$rex->cookies;	

		push @_,$1,"data";
		&send_file_uri_norange_chunked;
		return;		
	}
);

$public_table->add(qr<GET /ws>o=>sub {
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

		my $data="a" x 1024;#(1024*1024*4);
$public_table->add(qr{^GET /small$}o => sub{
		#my ($line, $rex)=@_;
		push @_, HTTP_OK,undef, $data;
		&rex_reply_simple;
		return;	
	}
);
		my $data2="a" x (1024*1024*4);
$public_table->add(qr{^GET /big$}o => sub{
		#my ($line, $rex)=@_;
		push @_, HTTP_OK,undef, $data2;
		&rex_reply_simple;
		return;	
	}
);



$public_table->add(qr{^PUT|POST /urlencoded}o=>sub {
		my ($line,$rex)=@_;
		push @_,undef, sub {
			state $previous_headers;
			state @chunks;
			if($_[1]!=$previous_headers){
				say "NEW SECTION";
				$previous_headers=$_[1];
				#new data chunk
				#chunk of data		
				push @chunks, $_[0];
			}
			elsif($_[0]//0){
				say "MORE DATA FOR EXisTING";
				#data to add to existing part
				push @chunks, $_[0];

			}
			else {
				say "END OF DATA";
				#end of response
				local $,=", ";
				say my @response=parse_form uri_decode join "", @chunks;
				#decode 
				rex_reply_simple $line, $rex, HTTP_OK,undef,"finished post: ".uc  join "", @response unless defined $_[0];
			}
		};

		&uSAC::HTTP::Rex::handle_urlencode_upload;
		return;
	}
);

$public_table->add( begins_with("POST /formdata")=>sub {
		say "FORM DATA ENDPOINT";
		my ($line,$rex)=@_;
		push @_, sub {
			state $previous_headers;
			if($_[1] != $previous_headers){
				say "NEW PART";
				$previous_headers=$_[1];
				#data here to be processed
			}
			elsif($_[0]//0){
				say "MORE DATA FOR EXISTING PART";
				#more data for existing part
			}
			else {
				say "MULTIPART END";
				#multipart complete
				rex_reply_simple $line, $rex, HTTP_OK,undef, "finished multipart form";
			}
		};

		&uSAC::HTTP::Rex::handle_form_upload;
		return;
	}
);





my $private_dispatcher=$private_table->prepare_dispatcher(type=>"online", cache=>{});
my $public_dispatcher=$public_table->prepare_dispatcher(type=>"online", cache=>{});

#make private stack
my ($authorised,$stack)= uSAC::HTTP::Middler->new()
	->register(\&authenticate_simple)	#one or more middleware 
	->link($private_dispatcher);		#Final dispatching

my $main_table=Hustle::Table->new(\&default_handler);

$main_table->add(qr{^GET /user} => $authorised);
$main_table->add(qr{^PUT|POST|GET .*}	=> $public_dispatcher);

my $dispatcher=$main_table->prepare_dispatcher(type=>"online",cache=>{});

my ($first,$stack)=uSAC::HTTP::Middler->new()
#->register(\&log_simple)
	->link($dispatcher);	#link and set default;

my $server = uSAC::HTTP::Server->new(
	host=>"0.0.0.0",
	port=>8080,
	cb=>$first
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

$cv->recv();
