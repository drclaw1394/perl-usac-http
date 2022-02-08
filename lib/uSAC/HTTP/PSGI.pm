package uSAC::HTTP::PSGI;
#PSGI adaptor for uSAC::HTTP::Server
use strict;
use warnings;
use feature qw<switch say refaliasing state>;
no warnings "experimental";
use List::Util qw<pairs first>;
use Data::Dumper;

use Exporter "import";

#use Stream::Buffered;	#From PSGI distribution
use Plack::TempBuffer;

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
		my $buffer=Plack::TempBuffer->new();


		state $psgi_version=[1,1];

		\my %env=$rex->[uSAC::HTTP::Rex::headers_];	#alias the headers as the environment

		$env{REQUEST_METHOD}=	$rex->[uSAC::HTTP::Rex::method_];
		$env{SCRIPT_NAME}=		"";
		$env{PATH_INFO}=		"";
		$env{REQUEST_URI}=		$rex->[uSAC::HTTP::Rex::uri_];
		$env{QUERY_STRING}=		$rex->[uSAC::HTTP::Rex::query_string_];
		$env{SERVER_NAME}=		"";
		$env{SERVER_PORT}=		"";
		$env{SERVER_PROTOCOL}=	$rex->[uSAC::HTTP::Rex::version_];

		#CONTENT_LENGTH=>	"",
		#CONTENT_TYPE=>		"",

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
		#my $res=$app->(\%env);
		#my ($code, $psgi_headers, $psgi_body)=
		my $res=$app->(\%env);

		#@$res;
		
		my $write=$_[1][uSAC::HTTP::Rex::write_];
		my $dropper=$_[1][uSAC::HTTP::Rex::session_][uSAC::HTTP::Session::dropper_];
		if(ref($res) eq  "CODE"){
			#delayed response
			$res->(sub {
					say Dumper @_;
					my $res=shift;
					if(@$res==3){
						do_array($usac, $rex, $res);
						return;
					}
					#streaming. return writer
					my $w=uSAC::HTTP::PSGI::Writer->new;
					return $w;
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
		#Process response 	
		#
		#
		#
	};
}
sub do_array {
	my ($usac,$rex, $res)=@_;
	my $write=$rex->[uSAC::HTTP::Rex::write_];
	my $dropper=$rex->[uSAC::HTTP::Rex::session_][uSAC::HTTP::Session::dropper_];
	my $session=$rex->[uSAC::HTTP::Rex::session_];
	my ($code, $psgi_headers, $psgi_body)=@$res;
	#Write After joining. Drop if required

	my $content=join"",@$psgi_body;
	#Check for content length header and add if not existing
	unless(first {/Content-Length/i}, @$psgi_headers)	{
		push @$psgi_headers, "Content-Length",length($content);
	}
	my @headers=pairs @$psgi_headers;
	rex_reply_simple $usac,$rex,$code,\@headers,$content;
	$session->pop_reader;
	#$write->(join("", $res->[2]->@*), $dropper);

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
1;
