package uSAC::HTTP::PSGI;
#PSGI adaptor for uSAC::HTTP::Server
use strict;
use warnings;
use feature qw<switch say refaliasing state>;
no warnings "experimental";
use List::Util qw<pairs first>;
use Data::Dumper;
$Data::Dumper::Deparse=1;

use Exporter "import";

use Stream::Buffered::PerlIO;	#From PSGI distribution
#use Plack::TempBuffer;

use uSAC::HTTP;
use uSAC::HTTP::Rex;
use uSAC::HTTP::Session;

use constant KEY_OFFSET=>0;
use enum ("entries_=".KEY_OFFSET, qw<end_>);
use constant KEY_COUNT=> end_-entries_+1;

use constant LF => "\015\012";
our @EXPORT_OK=qw<usac_to_psgi>;
our @EXPORT=@EXPORT_OK;

package uSAC::HTTP::PSGI::Writer {
use constant LF => "\015\012";
	#simple class to wrap the push write of the session
	sub new {
		my $package=shift;
		
		bless {@_},$package
	}
	sub write {
		my $self=shift;
		my $rex=$self->{rex};
		#TODO: make this a chunked write
		if($self->{keep_alive}){
			my $scratch=sprintf("%02X".LF,length $_[0]).$_[0].LF;
			$rex->writer->($scratch);
		}
		else {
			$rex->writer->($_[0]);
		}

	}

	sub close {
		my $self=shift;
		my $rex=$self->{rex};
		my $session=$rex->[uSAC::HTTP::Rex::session_];
		if($self->{keep_alive}){
			my $scratch=sprintf("%02X".LF,0).LF;
			$rex->writer->($scratch,
				sub {
					$session->[uSAC::HTTP::Session::dropper_]->();
				}
			);
		}
		else {
			#Force closure
			$session->[uSAC::HTTP::Session::closeme_]=1;
			$session->[uSAC::HTTP::Session::dropper_]->();
		}
		$session->pop_reader;
	}
}

#Driver to interface with PSGI based applications
#this acts as either middleware or an end point
sub usac_to_psgi {
	
	#PSGI application 
	my $app=pop;
	my %options=@_;
	if(ref($app)eq "CODE"){
	}
	else{

		#assume a file path
		$app=usac_path %options, $app;
		say "Attempting to load psgi: $app";
		unless($app=do $app){
			say STDERR "Could not load psgi";
			say STDERR $!;
			say STDERR $@;

		}
	}

	#TODO: options inclue using keepalive or not.

	#the sub returned is the endpoint in terms of the usac flow
	sub {
		my ($usac,$rex)=@_;	
		my $session=$rex->[uSAC::HTTP::Rex::session_];

		#buffer to become psgi.input
		#my $buffer=Plack::TempBuffer->new();
		my $buffer=Stream::Buffered::PerlIO->new();


		state $psgi_version=[1,1];

		\my %env=$rex->[uSAC::HTTP::Rex::headers_];	#alias the headers as the environment
		#remove /rename content length and content type for PSGI
		$env{CONTENT_LENGTH}=delete $env{HTTP_CONTENT_LENGTH()};
		$env{CONTENT_TYPE}=delete $env{HTTP_CONTENT_TYPE()};
		#
		$env{REQUEST_METHOD}=	$rex->[uSAC::HTTP::Rex::method_];
		$env{SCRIPT_NAME}=		"";
		$env{PATH_INFO}=		"";
		$env{REQUEST_URI}=		$rex->[uSAC::HTTP::Rex::uri_];
		$env{QUERY_STRING}=		$rex->[uSAC::HTTP::Rex::query_string_];

		my($host,$port)=split ":", $env{HTTP_HOST()};
		$env{SERVER_NAME}=	$host;
		$env{SERVER_PORT}=		$port;
		$env{SERVER_PROTOCOL}=	$rex->[uSAC::HTTP::Rex::version_];

		#CONTENT_LENGTH=>	"",
		#CONTENT_TYPE=>		"",

		#HTTP_HEADERS....

		$env{'psgi.version'}=		$psgi_version;
		$env{'psgi.url_scheme'}=	$session->[uSAC::HTTP::Session::scheme_];

		# the input stream.	Buffer?
		$env{'psgi.input'}=		$buffer;
		# the error stream.
                ###############################################
                # state $io=IO::Handle->new();                #
                # $io->fdopen(fileno(STDERR),"w") unless $io; #
                ###############################################
		$env{'psgi.errors'}=	*STDERR;#$io;
		$env{'psgi.multithread'}=	undef;
		$env{'psgi.multiprocess'}=	undef;
		$env{'psgi.run_once'}=	undef;
		$env{'psgi.nonblocking'}= 	1;
		$env{'psgi.streaming'}=	1;

		#Extensions
		$env{'psgix.io'}= "";
		$env{'psgix.input.buffered'}=1;
		state $logger=sub {};
		$env{'psgix.logger'}=		$logger;
		$env{'psgix.session'}=		{};
		$env{'psgix.session.options'}={};
		$env{'psgix.harakiri'}=		undef;
		$env{'psgix.harakiri.commit'}=		"";
		$env{'psgix.cleanup'}=undef;
		$env{'psgix.cleanup.handlers'}=	[];

		#Install the on_read method to stream body content to disk
		#The file/scalar/fh is then passed as the input to the psgi app
		#To support http/1.1, some sort of preprocessing is needed to mark 
		#an eof condition for psgi, but stream remains open
		
		#push and pump the reader immediately	
		uSAC::HTTP::Session::push_reader
		$session,
		sub {
			#Simply print the read event data to the buffer
			#It is up to the PSGI application to poll the 'filehandle'
			#for more data

			$buffer->print($_[1]);	
		};
		
		#Pump the reader for outstanding bytes we could process immediately
		$session->pump_reader;


		#Execute the PSGI application
		my $res=$app->(\%env);

		
		#my $write=$_[1][uSAC::HTTP::Rex::write_];
		#my $dropper=$session->[uSAC::HTTP::Session::dropper_];
		if(ref($res) eq  "CODE"){
			#delayed response
			$res->(sub {
					my $res=shift;
					if(@$res==3){
						do_array($usac, $rex, $res);
						return;
					}
					#streaming. return writer
					return do_streaming($usac,$rex, $res, \%options);
				});
			return

		}
		for(ref($res->[2])){
			if($_ eq "ARRAY"){
				do_array($usac,$rex, $res);
			}
			elsif($_ eq "GLOB"){
				do_glob($usac, $rex, $res);
			}
			else {
				say "unknown type";
			}
		}
	};
}
sub do_array {
	my ($usac,$rex, $res)=@_;
	my $session=$rex->[uSAC::HTTP::Rex::session_];

	#Check for content length header and add if not existing
        ###################################################################
        # unless(first {/Content-Length/i}, @$psgi_headers)       {       #
        #         push @$psgi_headers, "Content-Length",length($content); #
        # }                                                               #
        ###################################################################
	#@$psgi_headers;
	rex_write $usac,$rex,
		$res->[0],
		{pairs $res->[1]->@*},
		join "", $res->[2]->@*;

	$session->pop_reader;
}
sub do_glob {
	my ($usac,$rex, $res)=@_;
	my $write=$rex->[uSAC::HTTP::Rex::write_];
	my $dropper=$rex->[uSAC::HTTP::Rex::session_][uSAC::HTTP::Session::dropper_];
	my $session=$rex->[uSAC::HTTP::Rex::session_];
	my ($code, $psgi_headers, $psgi_body)=@$res;

	local $/=\4096;

	#setup headers

	my $reply="HTTP/1.1 $code".LF;

	unless(first {/Content-Length/i}, @$psgi_headers)	{
		#calculate the file size from stating it
		my $size=(stat $psgi_body)[7];
		push @$psgi_headers, "Content-Length",$size;
	}

	my @headers= pairs @$psgi_headers;
	$reply.= join "", map $_->[0].": ".$_->[1].LF, @headers;

	@headers=(
		[HTTP_DATE,		$uSAC::HTTP::Session::Date],
		($session->[uSAC::HTTP::Session::closeme_]
			?[HTTP_CONNECTION,	"close"]
			:([	HTTP_CONNECTION,	"Keep-Alive"],
				[HTTP_KEEP_ALIVE,	"timeout=10, max=1000"]
			)
		)
	);
	$reply.= join "", map $_->[0].": ".$_->[1].LF, @headers;
	$reply.=LF.<$psgi_body>;
	#setup reader to execute on callback
	my $do_it=sub{
		my $data=<$psgi_body>;
		if(length($data)){
			$write->($data, __SUB__);
		}
		else {
			close $psgi_body; 
			$session->pop_reader;
			$dropper->();

		}
	};
	$write->($reply,$do_it);
}

sub do_streaming {
	my ($usac,$rex, $res, $options)=@_;
	my $write=$rex->[uSAC::HTTP::Rex::write_];
	my $session=$rex->[uSAC::HTTP::Rex::session_];
	my $dropper=$session->[uSAC::HTTP::Session::dropper_];
	my ($code, $psgi_headers, $psgi_body)=@$res;

	my $reply="HTTP/1.1 $code".LF;


	my @headers= pairs @$psgi_headers;
	$reply.= join "", map $_->[0].": ".$_->[1].LF, @headers;

	@headers=(
		[HTTP_DATE,		$uSAC::HTTP::Session::Date],
		($options->{keep_alive}
			?([	HTTP_CONNECTION,	"Keep-Alive"],
				[HTTP_KEEP_ALIVE,	"timeout=10, max=1000"],
				[HTTP_TRANSFER_ENCODING, "chunked"],
			)
			:[HTTP_CONNECTION,	"close"]
		),

	);
	$reply.= join "", map $_->[0].": ".$_->[1].LF, @headers;
	$reply.=LF;

	#Write header and return writer object
	$write->($reply);

	my $w=uSAC::HTTP::PSGI::Writer->new(%$options, rex=>$rex);
	return $w;
}

1;
