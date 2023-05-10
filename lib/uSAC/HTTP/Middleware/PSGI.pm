package uSAC::HTTP::Middleware::PSGI;
use v5.36;
#PSGI adaptor for uSAC::HTTP::Server
use strict;
use warnings;
use feature qw<switch say refaliasing state>;
no warnings "experimental";
use Log::ger;
use Log::OK;
use Error::Show;

use List::Util qw<pairs first>;

use Exporter "import";

#use Stream::Buffered::PerlIO;	#From PSGI distribution
use Plack::TempBuffer;

use uSAC::HTTP;
use uSAC::HTTP::Rex;
use uSAC::HTTP::Session;
#use uSAC::HTTP::Middleware qw<chunked>;
use uSAC::HTTP::Constants;
use URL::Encode qw<url_decode_utf8 url_decode url_encode_utf8 url_encode>;

use constant KEY_OFFSET=>0;
use enum ("entries_=".KEY_OFFSET, qw<end_>);
use constant KEY_COUNT=> end_-entries_+1;

our @EXPORT_OK=qw<uhm_psgi>;
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
    $self->{next}( $self->{matcher}, $self->{rex}, $self->{in_header},$self->{headers}, my $a=$_[0], sub {});

    $self->{headers}=undef;

  }

  sub close {
    my $self=shift;
    my $rex=$self->{rex};
    my $session=$rex->[uSAC::HTTP::Rex::session_];
    #call with no callback to mark the end of chunked stream
    #Also need to pass defined but empty data
    rex_write( $self->{matcher}, $self->{rex}, $self->{in_header}, $self->{headers}, my $a="");

    #$session->[uSAC::HTTP::Session::closeme_]=1;
    $session->closeme=1;
    #$session->[uSAC::HTTP::Session::dropper_]->();	#no keep alive
    $session->dropper->();

  }
}

no warnings "experimental";
#Driver to interface with PSGI based applications
#this acts as either middleware or an end point
sub uhm_psgi {

  #PSGI application 
  my $app=pop;

  my %options=@_;
  if(ref($app)eq "CODE"){

  }
  else{

    #assume a file path
    my $path=usac_path %options, $app;
    Log::OK::INFO and log_info "Attempting to load psgi: $path";
		$app=eval "require '$path'";

    if(my $context=context){
      log_error "Could not load PSGI file $path: $app";
      die "Could not load PSGI file $path $!";	
    }
  }

  #TODO: options inclue using keepalive or not.

  #the sub returned is the endpoint in terms of the usac flow
  my %ctx;
  my $inner=sub {
    my $next=shift;
    sub {
      my ($usac, $rex, $in_header, $out_header)=@_;	
      
      my $ctx;
      my $env;
      my $buffer;
      my $header;

      if($_[HEADER]){
        #buffer to become psgi.input

        my $session=$_[REX]->session;#$rex->[uSAC::HTTP::Rex::session_];

        state $psgi_version=[1,1];

        \my %h=$_[IN_HEADER];
        my %env=map(("HTTP_".uc $_, $h{$_}), keys %h);

        $env{CONTENT_TYPE}//=delete $env{HTTP_CONTENT_TYPE};
        $env{CONTENT_LENGTH}//=delete $env{HTTP_CONTENT_LENGTH};

        $env=\%env;

        if($env{CONTENT_LENGTH}){
          #We have a body to process
          $buffer=Stream::Buffered->new($env{CONTENT_LENGTH});
          $ctx=$ctx{$_[REX]}=[ $env, $buffer, $_[HEADER]];
			    $_[REX][uSAC::HTTP::Rex::in_progress_]=1;
        }
        
          $_[HEADER]=undef;
        #
        # Do silly CGI convention here
        #
        my $path;
        my $query;
        my $uri=$_[REX][uSAC::HTTP::Rex::uri_raw_];
        #utf8::encode $uri;
        
        $uri=url_decode $uri;
        #$uri= url_encode $uri;
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


        $env{REQUEST_METHOD}=	$_[IN_HEADER]{":method"};#$_[REX]->[uSAC::HTTP::Rex::method_];
        $env{REQUEST_URI}=		$_[IN_HEADER]{":path"};#$_[REX]->[uSAC::HTTP::Rex::uri_raw_];
        

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

          $buffer->print($_[PAYLOAD]);
          unless($_[CB]){
            #last call, Actually call the application
            $env->{"psgi.input"}=$buffer->rewind; 
          }
          else {
            #Not last call. more to come. execute callback?
            #
            $_[CB]->(1);
            return;
          }
      }
      

        #Execute the PSGI application
        my $res=$app->($env);


        if(ref($res) eq  "CODE"){
          #DELAYED RESPONSE
          $res->(sub {
              my $res=shift;
              #Convert array of headers to hash
              $res->[1]={$res->[1]->@*};
              $res->[1]{":status"}=$res->[0];
              if(@$res==3){
                #DELAYED RESPONSE IS A 3 elemement response
                #$res->[1]{":status"}=$res->[0];
                $next->($usac, $rex, $in_header, $res->[1], join "", $res->[2]->@*);
                return;
              }

              #or it is streaming. return writer
              my ($code, $psgi_headers, $psgi_body)=@$res;
              uSAC::HTTP::Middleware::PSGI::Writer->new(%options,  in_header=>$in_header, headers=>$psgi_headers, rex=>$rex, matcher=>$usac, next=>$next);
            });
          return
        }

        for(ref($res->[2])){
          #Convert array of headers to hash
          $res->[1]={$res->[1]->@*};
          if($_ eq "ARRAY"){
            Log::OK::TRACE and log_trace "IN DO ARRAY";
            #do_array($usac, $rex, $res);
            $res->[1]{":status"}=$res->[0];
            $next->($usac, $rex, $in_header, $res->[1], join("", $res->[2]->@*),undef);
            #delete $ctx{$_[REX]} if $buffer;  #Immediate respose dispose of context if it was created
          }
          #elsif($_ eq "GLOB" or $res->[2] isa "IO::Handle"){
          else{
            Log::OK::TRACE and log_trace "DOING GLOB";
            do_glob($usac, $rex, $res, $next);
          }
        }
        delete $ctx{$_[REX]};




    };
  };

  my $outer=sub {
    my $next=shift;
  };

  my $error=sub {
    my $next=shift;
    sub {
        delete $ctx{$_[REX]};
        &$next;
    }
  };

  [$inner, $outer];
}


sub do_glob {
  Log::OK::TRACE and log_trace "IN DO GLOB";
	my ($usac, $rex, $res,$next)=@_;
	my $session=$rex->[uSAC::HTTP::Rex::session_];
	my $dropper=$session->dropper;

	my ($code, $psgi_headers, $psgi_body)=@$res;


	#setup headers


  unless(exists $psgi_headers->{HTTP_CONTENT_LENGTH()}){
    #unless(first {/Content-Length/i} @$psgi_headers)	{
		#calculate the file size from stating it
    if(ref($psgi_body) eq "GLOB" or $psgi_body isa IO::Handle){
      my $size=(stat $psgi_body)[7];
      $psgi_headers->{HTTP_CONTENT_LENGTH()}=$size;
      #push @$psgi_headers, HTTP_CONTENT_LENGTH, $size;
    }
	}

	
	local $/=\4096;
	my $data;
	my $do_it;
  $do_it=sub{
    unless (@_){
      Log::OK::TRACE and log_trace "ERROR CB";
      #callback error. Close file
        $psgi_body->close;
        $do_it=undef;
        $dropper->();
        return;
    }
		$data=$psgi_body->getline;#<$psgi_body>;
		if(defined($data) or length($data)){
      Log::OK::TRACE and log_trace "FILE READ: line: $data";
			$next->($usac, $rex, $code, $psgi_headers, $data, __SUB__);
      $psgi_headers=undef;
		}
		else {
      Log::OK::TRACE and log_trace "END OF GLOB";
      $do_it=undef;     #Release this sub
			$psgi_body->close; #close the file
      $psgi_body=undef;
      
      #Do the final write with no callback
			$next->($usac, $rex, $code, $psgi_headers, my $a="", my$b=undef);
      #$dropper->();
		}
	};
  $do_it->(undef);
}


1;
