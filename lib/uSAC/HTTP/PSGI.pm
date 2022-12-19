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
use uSAC::HTTP::Middleware qw<chunked>;
use uSAC::HTTP::Constants;

use constant KEY_OFFSET=>0;
use enum ("entries_=".KEY_OFFSET, qw<end_>);
use constant KEY_COUNT=> end_-entries_+1;

our @EXPORT_OK=qw<usac_to_psgi>;
our @EXPORT=@EXPORT_OK;

#This is to mimic a filehandle?
package uSAC::HTTP::PSGI::Writer {

  use uSAC::HTTP::Rex;
  use uSAC::HTTP::Constants;
  #simple class to wrap the push write of the session
  sub new {
    my $package=shift;

    bless {@_},$package
  }
  sub write {
    my $self=shift;
    my $rex=$self->{rex};

    #call with generic sub as callback to continue the chunks
    #rex_write( $self->{matcher}, $self->{rex}, $self->{code},$self->{headers}, $_[0], sub {});
    $self->{next}( $self->{matcher}, $self->{rex}, $self->{code},$self->{headers}, $_[0], sub {});

    $self->{headers}=undef;

  }

  sub close {
    my $self=shift;
    my $rex=$self->{rex};
    my $session=$rex->[uSAC::HTTP::Rex::session_];
    #call with no callback to mark the end of chunked stream
    #Also need to pass defined but empty data
    rex_write( $self->{matcher}, $self->{rex}, $self->{code}, $self->{headers}, "");

    #$session->[uSAC::HTTP::Session::closeme_]=1;
    $session->closeme=1;
    #$session->[uSAC::HTTP::Session::dropper_]->();	#no keep alive
    $session->dropper->();

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
  my %ctx;
  my $inner=sub {
    my $next=shift;
    sub {
      my ($usac, $rex)=@_;	
      
      unless($_[CODE]){
        #stack reset
        say "STACK RESET";
        delete $ctx{$_[REX]};
        &$next;
        return
      }

      if($_[HEADER]){
        #buffer to become psgi.input
        #my $buffer=Plack::TempBuffer->new();

        my $session=$_[REX]->session;#$rex->[uSAC::HTTP::Rex::session_];



        state $psgi_version=[1,1];

        my $buffer;
        \my %env=$_[REX]->headers;#[uSAC::HTTP::Rex::headers_];	#alias the headers as the environment
        #say join ", ", %env;
        #my %env=map(("HTTP_".$_, $h->{$_}), keys $h->%*);

        #remove /rename content length and content type for PSGI
        #$env{CONTENT_LENGTH}=delete $env{HTTP_CONTENT_LENGTH};
        #$env{CONTENT_TYPE}=delete $env{HTTP_CONTENT_TYPE};
        #

        if($env{CONTENT_LENGTH}){
          #We have a body to process
          $buffer=Stream::Buffered::PerlIO->new();
          $ctx{$_[REX]}//=$buffer;
        }
        $env{REQUEST_METHOD}=	$_[REX]->[uSAC::HTTP::Rex::method_];
        $env{SCRIPT_NAME}=		"";
        $env{PATH_INFO}=		"";
        $env{REQUEST_URI}=		$_[REX]->[uSAC::HTTP::Rex::uri_];
        $env{QUERY_STRING}=		$_[REX]->[uSAC::HTTP::Rex::query_string_];

        my($host,$port)=split ":", $env{HOST};
        $env{SERVER_NAME}=	$host;
        $env{SERVER_PORT}=		$port;
        $env{SERVER_PROTOCOL}=	$_[REX]->[uSAC::HTTP::Rex::version_];

        #CONTENT_LENGTH=>	"",
        #CONTENT_TYPE=>		"",

        #HTTP_HEADERS....

        $env{'psgi.version'}=		$psgi_version;
        $env{'psgi.url_scheme'}=	$session->scheme;#[uSAC::HTTP::Session::scheme_];

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



        #Execute the PSGI application
        my $res=$app->(\%env);


        if(ref($res) eq  "CODE"){
          #DELAYED RESPONSE
          $res->(sub {
              my $res=shift;
              if(@$res==3){
                #DELAYED RESPONSE IS A 3 elemement response
                $next->($usac, $rex, $res->[0], $res->[1], join "", $res->[2]->@*);
                return;
              }

              #or it is streaming. return writer
              my ($code, $psgi_headers, $psgi_body)=@$res;
              uSAC::HTTP::PSGI::Writer->new(%options, code=>$code, headers=>$psgi_headers, rex=>$rex, matcher=>$usac, next=>$next);
            });
          return
        }

        for(ref($res->[2])){
          if($_ eq "ARRAY"){
            #do_array($usac, $rex, $res);
            $next->($usac, $rex, $res->[0], $res->[1], join("", $res->[2]->@*),undef);
            delete $ctx{$_[REX]} if $buffer;  #Immediate respose dispose of context if it was created
          }
          elsif($_ eq "GLOB"){
            do_glob($usac, $rex, $res);
          }
          else {
            say "unknown type";
          }
        }
      }
      else {
          $ctx{$_[REX]}->print($_[PAYLOAD])
      }
    };
  };

  my $outer=sub {
    my $next=shift;
  };

  [$inner, $outer];
}

sub do_array {
	my ($usac,$rex, $res)=@_;
	my $session=$rex->[uSAC::HTTP::Rex::session_];

	rex_write $usac,$rex,
		$res->[0],
		$res->[1],
		join "", $res->[2]->@*;

}

sub do_glob {
	my ($usac, $rex, $res)=@_;
	my $session=$rex->[uSAC::HTTP::Rex::session_];
	my $dropper=$session->dropper;#$rex->[uSAC::HTTP::Rex::session_]->dropper;#[uSAC::HTTP::Session::dropper_];
	my ($code, $psgi_headers, $psgi_body)=@$res;


	#setup headers


	unless(first {/Content-Length/i}, @$psgi_headers)	{
		#calculate the file size from stating it
		my $size=(stat $psgi_body)[7];
		push @$psgi_headers, "Content-Length",$size;
	}

	
	local $/=\4096;
	my $data;
	my $do_it;
  $do_it=sub{
    unless (@_){
      #callback error. Close file
        close $psgi_body;
        $do_it=undef;
        $dropper->();
        return;
    }
		$data=<$psgi_body>;
		if(length($data)){
			rex_write($usac,$rex, $code, $psgi_headers, $data, __SUB__);
      $psgi_headers=undef;
		}
		else {
      $do_it=undef;
			close $psgi_body; 
			$dropper->();
		}
	};
  $do_it->(undef);
}

sub do_streaming {
	my ($usac,$rex, $res, $options)=@_;
	my $session=$rex->[uSAC::HTTP::Rex::session_];
	my $dropper=$session->dropper;#[uSAC::HTTP::Session::dropper_];
	my ($code, $psgi_headers, $psgi_body)=@$res;

	

	my $w=uSAC::HTTP::PSGI::Writer->new(%$options, code=>$code, headers=>$psgi_headers, rex=>$rex, matcher=>$usac);
	return $w;
}

1;
