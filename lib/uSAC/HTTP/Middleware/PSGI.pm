package uSAC::HTTP::Middleware::PSGI;
use v5.36;
#PSGI adaptor for uSAC::HTTP::Server
use strict;
use warnings;
use feature qw<switch say refaliasing state>;
no warnings "experimental";

use List::Util qw<pairs first>;

use Exporter "import";

#use Stream::Buffered::PerlIO;	#From PSGI distribution
use Plack::TempBuffer;

use uSAC::HTTP;
use uSAC::HTTP::Rex;
use uSAC::HTTP::Session;
use uSAC::HTTP::Middleware qw<chunked>;
use uSAC::HTTP::Constants;
use URL::Encode qw<url_decode_utf8 url_decode url_encode_utf8 url_encode>;

use constant KEY_OFFSET=>0;
use enum ("entries_=".KEY_OFFSET, qw<end_>);
use constant KEY_COUNT=> end_-entries_+1;

our @EXPORT_OK=qw<psgi>;
our @EXPORT=@EXPORT_OK;

#This is to mimic a filehandle?
package uSAC::HTTP::Middleware::PSGI::Writer {
no warnings "experimental";

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
    $self->{next}( $self->{matcher}, $self->{rex}, $self->{code},$self->{headers}, my $a=$_[0], sub {});

    $self->{headers}=undef;

  }

  sub close {
    my $self=shift;
    my $rex=$self->{rex};
    my $session=$rex->[uSAC::HTTP::Rex::session_];
    #call with no callback to mark the end of chunked stream
    #Also need to pass defined but empty data
    rex_write( $self->{matcher}, $self->{rex}, $self->{code}, $self->{headers}, my $a="");

    #$session->[uSAC::HTTP::Session::closeme_]=1;
    $session->closeme=1;
    #$session->[uSAC::HTTP::Session::dropper_]->();	#no keep alive
    $session->dropper->();

  }
}

no warnings "experimental";
#Driver to interface with PSGI based applications
#this acts as either middleware or an end point
sub psgi {

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
        delete $ctx{$_[REX]};
        &$next;
        return
      }
      my $ctx;
      my $env;
      my $buffer;
      if($_[HEADER]){
        #buffer to become psgi.input

        my $session=$_[REX]->session;#$rex->[uSAC::HTTP::Rex::session_];



        state $psgi_version=[1,1];

        #\my %env=$_[REX]->headers;#[uSAC::HTTP::Rex::headers_];	#alias the headers as the environment
        #say join ", ", %env;
        \my %h=$_[REX]->headers;
        my %env=map(("HTTP_".$_, $h{$_}), keys %h);
        $env{CONTENT_TYPE}=delete $env{HTTP_CONTENT_TYPE};
        $env{CONTENT_LENGTH}=delete $env{HTTP_CONTENT_LENGTH};

        $env=\%env;

        if($env{CONTENT_LENGTH}){
          say STDERR "++_+_+_+_+_+_ CONTENT LENGTH";
          #We have a body to process
          $buffer=Stream::Buffered->new($env{CONTENT_LENGTH});
          $ctx=$ctx{$_[REX]}=[ $env, $buffer];
        }
        
        #
        # Do silly CGI convention here
        #
        my $path;
        my $query;
        my $uri=$_[REX][uSAC::HTTP::Rex::uri_raw_];
        #utf8::encode $uri;
        
        $uri=url_decode $uri;
        #$uri= url_encode $uri;
        say STDERR "REENCODED: ".$uri;
        my $index=index $uri, "?";
        if($index>=0){
          #Split
          $path=substr $uri,0, $index;
          $query=substr $uri, $index+1;
          #($path, $query)=split $_, "?", 2;
        }
        else {
          #No query
          $path=$uri;
        }
        $env{SCRIPT_NAME}="";
        #utf8::encode $path;
        #$path=url_encode_utf8 $path;
        #utf8::encode $path;
        $env{PATH_INFO}=$path;

        ####################################################
        # my $count=split "/", $path;                      #
        #                                                  #
        # #Find the second slash, the first after the root #
        # my $index=index $path, "/", 1;                   #
        # #if($index>=0){                                  #
        # if($count>2){                                    #
        #                                                  #
        #   #we have an 'application'                      #
        #   $env{SCRIPT_NAME}=substr $path, 0, $index;     #
        #   $env{PATH_INFO}=substr $path, $index;          #
        # }                                                #
        # else {                                           #
        #   #No application                                #
        #   #$index=0;                                     #
        #   $env{SCRIPT_NAME}="";                          #
        #   $env{PATH_INFO}=$path;#substr $_, $index+1;    #
        # }                                                #
        ####################################################

        $env{REQUEST_METHOD}=	$_[REX]->[uSAC::HTTP::Rex::method_];
        $env{REQUEST_URI}=		$_[REX]->[uSAC::HTTP::Rex::uri_raw_];
        
        say STDERR "requst url: ".$env{REQUEST_URI};

        $env{QUERY_STRING}=		$_[REX][uSAC::HTTP::Rex::query_string_];

        my($host,$port)=split ":", $env{HTTP_HOST};
        $env{SERVER_NAME}=	$host;
        $env{SERVER_PORT}=		$port;
        $env{SERVER_PROTOCOL}=	$_[REX]->[uSAC::HTTP::Rex::version_];

        #CONTENT_LENGTH=>	"",
        #CONTENT_TYPE=>		"",

        #HTTP_HEADERS....

        $env{'psgi.version'}=		$psgi_version;
        $env{'psgi.url_scheme'}=	$session->scheme;#[uSAC::HTTP::Session::scheme_];

        # the input stream.	Buffer?
        $env{'psgi.input'}=		undef;#$buffer;
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


        #return if $env{CONTENT_LENGTH};

      }
      

      if($ctx//=$ctx{$_[REX]}){
        $env=$ctx->[0];
        $buffer=$ctx->[1];
          $buffer->print($_[PAYLOAD][1]);
          unless($_[CB]){
            #last call, Actually call the application
            $env->{"psgi.input"}=$buffer->rewind; 
          }
          else {
            #Not last call. more to come. execute callback?
            $_[CB]->(1);
            return;
          }
      }
      

        #Execute the PSGI application
        
        my $res;
        $res=eval{$app->($env)};

        say STDERR $@ unless defined($res);
        &rex_error_internal_server_error
          if(!defined($res) and $@);



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
              uSAC::HTTP::Middleware::PSGI::Writer->new(%options, code=>$code, headers=>$psgi_headers, rex=>$rex, matcher=>$usac, next=>$next);
            });
          return
        }

        for(ref($res->[2])){
          if($_ eq "ARRAY"){
            #do_array($usac, $rex, $res);
            $next->($usac, $rex, $res->[0], $res->[1], join("", $res->[2]->@*),undef);
            #delete $ctx{$_[REX]} if $buffer;  #Immediate respose dispose of context if it was created
          }
          elsif($_ eq "GLOB" or $res->[2] isa "IO::Handle"){
            say STDERR "++++++DOING GLOB";
            do_glob($usac, $rex, $res);
          }
          else {
            say "unknown type $_";
          }
        }
        delete $ctx{$_[REX]};




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


	unless(first {/Content-Length/i} @$psgi_headers)	{
		#calculate the file size from stating it
		my $size=(stat $psgi_body)[7];
		push @$psgi_headers, HTTP_CONTENT_LENGTH, $size;
	}

	
	local $/=\4096;
	my $data;
	my $do_it;
  $do_it=sub{
    say STDERR " IN DO IT SUB ++++++";
    unless (@_){
      #callback error. Close file
        close $psgi_body;
        $do_it=undef;
        $dropper->();
        return;
    }
		$data=<$psgi_body>;
		if(length($data)){
			rex_write($usac, $rex, $code, $psgi_headers, $data, __SUB__);
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


1;
