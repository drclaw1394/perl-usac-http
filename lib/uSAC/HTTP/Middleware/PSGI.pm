package uSAC::HTTP::Middleware::PSGI;
use v5.36;

#PSGI adaptor for uSAC::HTTP::Server
use strict;
use warnings;

use feature qw<say refaliasing state>;
no warnings "experimental";
use Log::ger;
use Log::OK;
use Error::Show;



#use Stream::Buffered::PerlIO;	#From PSGI distribution
use Plack::TempBuffer;
use uSAC::IO;
use Import::These "uSAC::", "Util", "::HTTP::", qw<Rex Session Constants>;
use URL::Encode qw<url_decode_utf8 url_decode url_encode_utf8 url_encode>;
use Encode qw<encode>;


use Export::These qw<uhm_psgi>;




# TODO fix this hack
#

#This is to mimic a filehandle?
package uSAC::HTTP::Middleware::PSGI::Writer {
  no warnings "experimental";

  use Import::These qw<uSAC::HTTP:: Rex Constants>;
  use Log::ger;
  use Log::OK;

  #simple class to wrap the push write of the session
  sub new {
    my $package=shift;

    bless {@_},$package
  }

  sub write {
    my $self=shift;
    my $rex=$self->{rex};

    #call with generic sub as callback to continue the chunks
    Log::OK::TRACE and log_trace ("Writer called: ".join ", ", @_);
    $self->{next}( $self->{matcher}, $self->{rex}, $self->{in_header},$self->{headers}, my $a=$_[0], sub {});

    $self->{headers}=undef;

  }

  sub close {
    my $self=shift;
    Log::OK::TRACE and log_trace ("Write closed");
    my $rex=$self->{rex};
    my $session=$rex->[uSAC::HTTP::Rex::session_];
    #call with no callback to mark the end of chunked stream
    #Also need to pass defined but empty data
    #rex_write( $self->{matcher}, $self->{rex}, $self->{in_header}, $self->{headers}, my $a="");

    $session->closeme=1;
    $session->dropper->(undef);
  }
}

no warnings "experimental";
#Driver to interface with PSGI based applications
#this acts as either middleware or an end point
sub uhm_psgi {

  #PSGI application 
  my $app=pop;

  my %options=@_;
  my $ref=ref $app;

  if($ref eq "CODE"){
    #Assume a code ref
  }
  elsif($ref eq "SCALAR" or $ref eq "") {
    # Assume a simple scalar or reference to one

    #assume a file path
    my $path=uSAC::Util::path $app, [caller];

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
  my $psgi_version=[1,1];
  my $logger=sub {};
  my $inner=sub {
    my $next=shift;
    sub {
      my ($usac, $rex, $in_header, $out_header)=@_;	
      
      my $ctx;
      my $env;

      if($_[HEADER]){
        my $session=$_[REX]->session;
        $env=$_[IN_HEADER];

        # Convert / create he environmen variables which
        # did not originate from the client or have special meaning
        #
        $env->{'psgi.url_scheme'}=	$env->{":scheme"};
        $env->{REQUEST_METHOD}=	$env->{":method"};

        $env->{REQUEST_URI}=$env->{":path"};

        $env->{PATH_INFO}=url_decode($env->{":path"});

        $env->{SERVER_PROTOCOL}=$env->{":protocol"};
        $env->{QUERY_STRING}=	$env->{":query"};	
        ($env->{SERVER_NAME}, $env->{SERVER_PORT})=split ":", $env->{":authority"};

        $env->{CONTENT_TYPE}//=delete $env->{HTTP_CONTENT_TYPE};
        $env->{CONTENT_LENGTH}//=delete $env->{HTTP_CONTENT_LENGTH};


        if($env->{CONTENT_LENGTH}){
          #We have a body to process
          my $buffer=Stream::Buffered->new($env->{CONTENT_LENGTH});
          $ctx=$ctx{$_[REX]}=[ $env, $buffer, $_[HEADER]];
          $_[REX][uSAC::HTTP::Rex::in_progress_]=1;

          # the input stream.     Buffer?
          $env->{'psgi.input'}= $buffer;
        }
        else {
          $ctx=0;
          $env->{'psgi.input'}= undef;
        }
        
        #$_[OUT_HEADER]=undef;

        $env->{SCRIPT_NAME}="";
        $env->{'psgi.version'}=		$psgi_version;
        $env->{'psgi.errors'}=      *STDERR;#$io;
        $env->{'psgi.multithread'}= undef;
        $env->{'psgi.multiprocess'}=undef;
        $env->{'psgi.run_once'}=  undef;
        $env->{'psgi.nonblocking'}=       1;
        $env->{'psgi.streaming'}= 1;

        #Extensions
        #$env->{'psgix.io'}= "";
        #$env->{'psgix.input.buffered'}=1;
        #$env->{'psgix.logger'}=           $logger;
        #$env->{'psgix.session'}=          {};
        #$env->{'psgix.session.options'}={};
        #$env->{'psgix.harakiri'}=         undef;
        #$env->{'psgix.harakiri.commit'}=          "";
        #$env->{'psgix.cleanup'}=undef;
        #$env->{'psgix.cleanup.handlers'}= [];


        #return if $env{CONTENT_LENGTH};

      }
      

      if($ctx//=$ctx{$_[REX]}){
        $env=$ctx->[0];
        my $buffer=$ctx->[1];

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
        Log::OK::TRACE and log_trace "PSGI CODE response";
        #DELAYED RESPONSE
        $res->(sub {
            Log::OK::TRACE and log_trace "PSGI CODE response->call";
            my $res=shift;
            #Convert array of headers to hash
            #$res->[1]={$res->[1]->@*};
            my %h;
            for my ($k, $v)($res->[1]->@*){
              \my $e=\$h{$k};
              $e=$e
                ?join ", ", $e, $v
                : $v;
            }
            my $_connection=$_[OUT_HEADER]{HTTP_CONNECTION()};
            $h{HTTP_CONNECTION()}=$_connection if $_connection;
            $res->[1]=\%h;
            $res->[1]{":status"}=$res->[0];

            if(@$res==3){
              Log::OK::TRACE and log_trace "PSGI CODE response->call is 3 element (delayed)";
              #DELAYED RESPONSE IS A 3 elemement response
              #$res->[1]{":status"}=$res->[0];
              $next->($usac, $rex, $in_header, $res->[1], join "", $res->[2]->@*);
              return;
            }
            Log::OK::TRACE and log_trace "PSGI CODE response->call is 2 element (stream)";

            #or it is streaming. return writer
            my ($code, $psgi_headers, $psgi_body)=@$res;
            return uSAC::HTTP::Middleware::PSGI::Writer->new(
              %options,
              in_header=>$in_header,
              headers=>$psgi_headers,
              rex=>$rex,
              matcher=>$usac,
              next=>$next
            );
          });
        return
      }

      my %h;
      for(ref($res->[2])){
        #Convert array of headers to hash. Join multiple headers
        # NOTE This does not work for SET-COOKIE
        for my ($k, $v)($res->[1]->@*){
          \my $e=\$h{$k};
          $e=$e
            ?join ", ", $e, $v
            : $v;
        }
        my $_connection=$_[OUT_HEADER]{HTTP_CONNECTION()};
        $h{HTTP_CONNECTION()}=$_connection if $_connection;
        $res->[1]=\%h;
        $res->[1]{":status"}=$res->[0];

        if($_ eq "ARRAY"){
          Log::OK::TRACE and log_trace "IN DO ARRAY";
          #do_array($usac, $rex, $res);
          $next->($usac, $rex, $in_header, $res->[1], join("", $res->[2]->@*), undef);
        }
        else{
          Log::OK::TRACE and log_trace "DOING GLOB";
          do_glob($usac, $rex, $env, $res, $next);
          delete $ctx{$_[REX]} if $ctx;
        }
      }
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
	my ($usac, $rex, $env, $res, $next)=@_;
	my $session=$rex->[uSAC::HTTP::Rex::session_];
	my $dropper=$session->dropper;

	my ($code, $psgi_headers, $psgi_body)=@$res;

  #$psgi_headers->{":status"}=$code;

	#setup headers


  # User supplied headers could be mixed case... so regex match it is
  unless(grep /Content-Length/i, $psgi_headers->%*){
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
  #say "DO IT";
    unless (@_){
      Log::OK::TRACE and log_trace "ERROR CB";
      #callback error. Close file
        $psgi_body->close;
        $do_it=undef;
        $dropper->();
        return;
    }
		$data=$psgi_body->getline;#<$psgi_body>;
		if(defined($data) ){#or length($data)){
      #Log::OK::TRACE and log_trace "FILE READ: line: $data";
      #Log::OK::FATAL and log_fatal "FILE READ: line: $data";
      #
      my $s="$data";# STRANGE BUG work around

      $next->($usac, $rex, $env, $psgi_headers, $s, $do_it);
      $psgi_headers=undef;
		}
		else {
      Log::OK::TRACE and log_trace "END OF GLOB";
      $psgi_body->close; #close the file
      $psgi_body=undef;
      
      #Do the final write with no callback
      $next->($usac, $rex, $env, $psgi_headers, my $a="", my $b=undef);
      $do_it=undef;     #Release this sub
		}
	};
  $do_it->(undef);
}


1;
