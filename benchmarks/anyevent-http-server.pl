#!/usr/bin/env perl
use common::sense;
use feature "refaliasing";
no warnings "experimental";
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
use uSAC::HTTP::v1_1_Reader;
use uSAC::HTTP::Static;
use uSAC::HTTP::Server::WS;
use Hustle::Table;


use constant LF=>"\015\012";

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
		push @_, (HTTP_NOT_FOUND,"Go away: $rex->[uSAC::HTTP::Rex::method_]");
		&uSAC::HTTP::Rex::reply_simple;#h $rex, ;
});

$table->add(qr{^GET /data/$path}ao=> sub {
		#\my $line=\$_[0];
		#\my $rex=\$_[1];
		push @_,$1,"data";
		&send_file_uri2;
		return;		
	}
);
$table->add(qr<GET /ws>=>sub {
		#create a web socket here
		#once created, the callback is called with the ws object	

		#check the headers if this is allowed
		#

		#Then do the handshake or error otherwise
		#
		push @_, "/ws", sub {
			#reader callback
		};
		&upgrade_to_websocket;

	}
);

my $data="a" x 1024;
$table->add(qr{^GET $path}ao => sub{
		#my ($line, $rex)=@_;
		#\my $line=\$_[0];
		#\my $rex=\$_[1];
		#headers todo:
		push @_, HTTP_OK, undef, $data;
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


my $dispatcher=$table->prepare_dispatcher;

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
