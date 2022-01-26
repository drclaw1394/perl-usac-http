package uSAC::HTTP::PSGI;
#PSGI adaptor for uSAC::HTTP::Server
use strict;
use warnings;
use feature qw<switch say refaliasing state>;
no warnings "experimental";

use Stream::Buffered;	#From PSGI distribution

use uSAC::HTTP;
use uSAC::HTTP::Rex;
use uSAC::HTTP::Session;

use constant KEY_OFFSET=>0;
use enum ("entries_=".KEY_OFFSET, qw<end_>);
use constant KEY_COUNT= end_-entries_+1;

package uSAC::HTTP::PSGI::Writer {
	#simple class to wrap the push write of the session
	sub new {

	}
	sub write {
		my ($self)=@_;
	}
}

#Driver to interface with PSGI based applications
#this acts as either middleware or an end point
sub usac_to_psgi {
	
	#only option is the psgi applcation to call.. might be middleware
	my $app=shift;


	#the sub returned is the endpoint in terms of the usac flow
	sub {
		my ($usac,$rex)=@_;	
		my $session=$rex->[uSAC::HTTP::Rex::session_];

		#buffer to become psgi.input
		my $buffer=Plack::TempBufferi->new();


		state $psgi_version=[1,1];

		\my %env=\$rex->[uSAC::HTTP::Rex::headers_];	#alias the headers as the environment

		$env{REQUEST_METHOD}=	$rex->[uSAC::HTTP::Rex::method_];
		$env{SCRIPT_NAME}=		"";
		$env{PATH_INFO}=		"";
		$env{REQUEST_URI}=		$rex->[uSAC::HTTP::Rex::uri_];
		$env{QUERY_STRING}=		$rex->[uSAC::HTTP::Rex::query_stirng_];
		$env{SERVER_NAME}=		"";
		$env{SERVER_PORT}=		"";
		$env{SERVER_PROTOCOL}=	$rex->[uSAC::HTTP::Rex::version_];

		#CONTENT_LENGTH=>	"",
		#CONTENT_TYPE=>		"",
j
		#HTTP_HEADERS....

		$env{'psgi.version'}=	$psgi_version;
		$env{'psgi.url_scheme'}=	"";

		# the input stream.	Buffer?
		$env{'psgi.input'}=		"";
		# the error stream.
		$env{'psgi.errors'}=		"";
		$env{'psgi.multithreaded'}=	undef;
		$env{'psgi.multiproess'}=	undef;
		$env{'psgi.run_once'}=	undef;
		$env{'psgi.nonblocking'}= 	1;
		$env{'psgi.streaming'}=	1;

		#Extensions
		$env{'psgix.io'}= "";
		$env{'psgix.input.buffered'}=1;
		$env{'psgix.logger'}=		sub{};
		$env{'psgix.session'}=		{};
		$env{'psgix.session.options'}={}
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
		}
		
		#Pump the reader for outstanding bytes we could process immediately
		$session->pump_reader;


		#Execute the PSGI application
		my ($code,$headers,$content)=$app->(\%env);
		
		#Process response 	
		#
		#
		#
	};
}
1;
