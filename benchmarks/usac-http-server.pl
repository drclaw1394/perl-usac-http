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

my $cv=AE::cv;

use constant LF=>"\015\012";

given(\%uSAC::HTTP::Server::Session::make_writer_reg){
	$_->{http1_1_static_writer}=\&make_static_file_writer;
}

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


my $table=Hustle::Table->new();

$table->set_default( sub {
		my ($line,$rex)=@_;
		say "DEFAULT: $line";
		push @_, (HTTP_NOT_FOUND,undef,"Go away: $rex->[uSAC::HTTP::Rex::method_]");
		&rex_reply_simple;#h $rex, ;
});

$table->add(qr{^GET /login}o => sub {
		#set a cookie
		my @cookies=(
			new_cookie( test=>"value",	 	COOKIE_EXPIRES, time+60),
			new_cookie( another=>"valucawljksdfe",	COOKIE_MAX_AGE, 1000),
		);

		#add response, headers, body  and send it
		push @_, (HTTP_OK,
			[map {(HTTP_SET_COOKIE,$_->serialize_set_cookie)} @cookies #cookies
			],
			"HELLO");

		&rex_reply_simple;
	}
);

$table->add(qr{^GET /data/$path}o=> sub {
		#\my $line=\$_[0];
		\my $rex=\$_[1];

		my $cookies=$rex->cookies;	

		push @_,$1,"data";
		&send_file_uri_norange;
		return;		
	}
);

$table->add(qr<GET /ws>o=>sub {
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

$table->add(qr{^GET /$}o => sub{
		#my ($line, $rex)=@_;
		my $data="a" x 1024;
		push @_, HTTP_OK,undef, $data;
		&rex_reply_simple;
		return;	
	}
);



my ($first,$stack)=do {
	my $middler=uSAC::HTTP::Middler->new();
	$middler->register(\&make_mw_authenticate);
	$middler->link(sub {
			my $rex=$_[1];
			if($rex->cookies->{test} eq "value"){
				push @_, HTTP_OK, undef, "premission granted";
			}
			else {
				push @_, HTTP_FORBIDDEN, undef, "bzzzzzzz";
			}
			&rex_reply_simple;
		}
	);
};
$table->add(qr{GET /restricted}o => sub {
		\my $line=\$_[0];
		my $rex=$_[1];
		&$first;


	}
);
$table->add(qr{^GET /logout}o=>sub{
	#send expiry on all known cookies of intrest
	my @cookies=expire_cookies qw<test another>;

	#add response, headers, body  and send it
	push @_, (HTTP_OK,	#this should be a  redirect to a login/ landing page?
		[map {(HTTP_SET_COOKIE,$_->serialize_set_cookie)} @cookies #cookies
		],
		"HELLO");

	&rex_reply_simple;
}
);

$table->add(qr{^POST /urlencoded}o=>sub {
		my ($line,$rex)=@_;
		#my $rex=$_[1];
		#Check permissions, sizes etc?
		push @_, sub {

			rex_reply_simple $line, $rex, HTTP_OK,undef,"finished post" unless defined $_[0];
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
					rex_reply_simple $line, $rex, HTTP_OK,"finished multipart form";
				}
			};

			&uSAC::HTTP::Rex::handle_form_upload;
			return;
		}
);


my $dispatcher=$table->prepare_dispatcher(type=>"online",cache=>{});



sub make_mw_log {
	my $next=shift;	#This is the next mw in the chain
	my $last=shift;	#The last/target. for bypassing
	say "making log";
	sub {
		#this sub input is line, and rex
		#
		say "Request for resource: \"$_[0]\" @ ", time;
		return &$next;		#alway call next. this is just loggin
	}
}

sub make_mw_authenticate {
	my $next=shift;
	my $last=shift;
	say "making authenticate with next: ", $next; 
	sub {
		#this sub input is line, and rex
		my $rex=$_[1];
		my $cookies=parse_cookie $rex->headers->{cookie};
		#check that the current ip address of the client is the same as previously set?
		#
		return &$next;		#alway call next. this is just loggin
	}
}

my $middler=uSAC::HTTP::Middler->new();
$middler->register(\&make_mw_log);
#$middler->register(\&make_mw_authenticate);

my ($first,$stack)=$middler->link($dispatcher);	#link and set default;

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
