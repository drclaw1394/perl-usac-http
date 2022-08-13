package uSAC::HTTP::Rex;
use warnings;
use strict;
use version; our $VERSION = version->declare('v0.1');
use feature qw<current_sub say refaliasing state>;
no warnings "experimental";
our $UPLOAD_LIMIT=10_000_000;
use Log::ger;
use Log::OK;

use Try::Catch;
use Carp qw<carp>;
use File::Basename qw<basename dirname>;
use File::Spec::Functions qw<rel2abs>;
use uSAC::HTTP::Code qw<:constants>;
use uSAC::HTTP::Header qw<:constants>;
use uSAC::HTTP::v1_1_Reader;
#use uSAC::HTTP::Server;
use constant LF => "\015\012";


use uSAC::HTTP::Session;
#use uSAC::HTTP::Server;
use uSAC::HTTP::Cookie qw<:all>;

#use uSAC::HTTP::Static;
use AnyEvent;
use Exporter 'import';
use File::Temp qw<tempfile>;
use File::Path qw<make_path>;

use Data::Dumper;
use URL::Encode::XS;
use URL::Encode qw<url_decode_utf8>;

our @EXPORT_OK=qw<rex_headers 

usac_data_stream
usac_multipart_stream
usac_urlencoded_stream
usac_form_stream

usac_data_slurp
usac_multipart_slurp
usac_urlencoded_slurp
usac_form_slurp

rex_parse_form_params 
rex_query_params

rex_site_url
rex_site
rex_state

rex_redirect_see_other
rex_redirect_found
rex_redirect_temporary
rex_redirect_not_modified

rex_error_not_found
rex_error_internal_server_error 

rex_redirect_internal

rex_reply_json
rex_reply_html
rex_reply_javascript
rex_reply_text

rex_captures
rex_write
>;
our @EXPORT=@EXPORT_OK;




use Time::HiRes qw/gettimeofday/;
use Scalar::Util qw(weaken);
use Encode qw<decode encode decode_utf8>;


#Class attribute keys
#method_ uri_
#ctx_ reqcount_ 
use enum (
	"version_=0" ,qw< session_ headers_ write_ query_ query_string_ time_ cookies_ handle_ attrs_ host_ method_ uri_stripped_ uri_ state_ in_set_ in_used_ out_set_ out_used_ captures_ id_
	closeme_
	dropper_
	server_
	rex_
	in_progress_

	response_code_
	recursion_count_
	end_
	>
);

#Add a mechanism for sub classing
use constant KEY_OFFSET=>0;
use constant KEY_COUNT=>end_-version_+1;

require uSAC::HTTP::Middleware;
		
#Main output subroutine
#Arguments are matcher, rex, code, header, data, cb
#		0     ,	 1 ,	2,	3,    4,  5
sub rex_write{
	my $session=$_[1]->[session_];
	if($_[3]){
		#\my @h=$_[3];


		#If headers are supplied, then  process headers
		Log::OK::TRACE and log_trace "REX: Doing rex write====";
		#Log::OK::TRACE and log_trace "REX: close me: ".$session->[uSAC::HTTP::Session::closeme_];
		#$session->[uSAC::HTTP::Session::in_progress_]=1;
		$_[1][in_progress_]->$*=1;

		#Tell the other end the connection will be closed
		push $_[3]->@*, HTTP_CONNECTION, "close" if($_[1][closeme_]->$*);

		#Hack to get HTTP/1.0 With keepalive working
		push $_[3]->@*, HTTP_CONNECTION, "Keep-Alive" if($_[1][version_] eq "HTTP/1.0" and !$_[1][closeme_]->$*);

	}


	#Otherwise this is just a body call
	#
	

	&{$_[0][1][2]};	#Execute the outerware for this site/location

	#1;	#always return true
}
##
#OO Methods
#


# Returns the headers parsed at connection time
sub headers {
	return $_[0]->[headers_];
}
sub method {
	$_[0][method_];
}
sub uri{
	$_[0][uri_];
}
sub uri_stripped {
	$_[0][uri_stripped_];
}

#Returns parsed query parameters. If they don't exist, they are parse first
sub query_params {
	unless($_[1][query_]){
		#NOTE: This should already be decoded so no double decode
		#$_[1][query_]={};
		for ($_[1][query_string_]){
			#tr/ //d;

                        ##############################################
                        # for my $pair (split "&"){                  #
                        #         my ($key,$value)=split "=", $pair; #
                        #         $_[1][query_]{$key}=$value;        #
                        #                                            #
                        # }                                          #
                        ##############################################
			$_[1][query_]->%*=map ((split /=/a)[0,1], split /&/a);
		}
	}

	$_[1][query_];
}

#Builds a url based on the url of the current site/group
#match, rex, partial url
#Append partial url to end if supplied
#otherwise return the site prefix with no ending slash
sub rex_site_url {
	#match_entry->context->site->built_prefix
	#my $url= $_[0][4][0]->built_prefix;
	my $url= $_[0][1][0]->built_prefix;
	if($_[2]//""){
		return "$url/$_[2]";
	}
	$url;
	#$_[0][4][0]->built_prefix."/".($_[3]//"");
}

#returns the site object associate with this request
#match, rex, na
sub rex_site {
	$_[0][1][0];	
}

sub rex_state :lvalue{
	$_[1][state_];
}

#redirect to within site
#match entry
#rex
#partial url
#code
	
#TODO: "Multiple Choice"=>300,

sub rex_redirect_moved{
	my $url=pop;
	$_[2]=HTTP_MOVED_PERMANENTLY;
	push $_[3]->@*, HTTP_LOCATION, $url, HTTP_CONTENT_LENGTH, 0;
	rex_write (@_,"");
}

sub rex_redirect_see_other{
	my $url=pop;
	$_[2]=HTTP_SEE_OTHER;
	push $_[3]->@*, HTTP_LOCATION, $url, HTTP_CONTENT_LENGTH, 0;
	rex_write (@_,"");
}

sub rex_redirect_found {
	my $url=pop;
	$_[2]=HTTP_FOUND;
	push $_[3]->@*, HTTP_LOCATION, $url, HTTP_CONTENT_LENGTH, 0;

	rex_write (@_,"");
	
}

sub rex_redirect_temporary {
	my $url=pop;
	$_[2]=HTTP_TEMPORARY_REDIRECT;
	push $_[3]->@*, HTTP_LOCATION, $url, HTTP_CONTENT_LENGTH, 0;

	rex_write (@_,"");
	
}
sub rex_redirect_permanent {
	my $url=pop;
	$_[2]=HTTP_PERMANENT_REDIRECT;
	push $_[3]->@*, HTTP_LOCATION, $url, HTTP_CONTENT_LENGTH, 0;
	rex_write (@_,"");
	
}

sub rex_redirect_not_modified {
	my $url=pop;
	$_[2]=HTTP_NOT_MODIFIED;
	push $_[3]->@*, HTTP_LOCATION, $url, HTTP_CONTENT_LENGTH, 0;
	rex_write (@_,"");
}

sub rex_redirect_internal;


#General error call, Takes an additional argument of new status code
sub rex_error {
	my $site=$_[0][1][0];
	$_[1][method_]="GET";
	$_[2]=pop//HTTP_NOT_FOUND;	#New return code is appened at end
	
	#Locate applicable site urls to handle the error
	my $uri=$site->error_uris->{$_[2]};
	return rex_redirect_internal @_, $uri if $uri;
	
	#If one wasn't found, then make an ugly one
	rex_write (@_, 'Error: '.$_[2]);

}

sub rex_error_not_found {
	push @_, HTTP_NOT_FOUND;
	&rex_error;
}

sub rex_error_forbidden {
	push @_, HTTP_FORBIDDEN;
	&rex_error;
}

sub rex_error_internal_server_error {
	push @_, HTTP_INTERNAL_SERVER_ERROR;
	&rex_error;
	$_[1][closeme_]->$*=1;
	$_[1][dropper_](undef);
}


#Rewrites the uri and matches through the dispatcher
#TODO: recursion limit
sub rex_redirect_internal {

	my ($matcher, $rex, $code, $headers, $uri)=@_;
	#state $previous_rex=$rex;
	if(substr($uri,0,1) ne "/"){
		$uri="/".$uri;	
	}
	$rex->[uri_]=$uri;
	$rex->[uri_stripped_]=$uri;
	if(($rex->[recursion_count_]) > 10){
		$rex->[recursion_count_]=0;
		#carp "Redirections loop detected for $uri";
		Log::OK::ERROR and log_error("Loop detected. Last attempted url: $uri");	
		rex_write($matcher, $rex, HTTP_LOOP_DETECTED, [HTTP_CONTENT_LENGTH, 0],"");
		return;
	}

	#Here we reenter the main processing chain with a  new url, potentiall
	#new headers and status code
	undef $_[0];
	Log::OK::DEBUG and  log_debug "Redirecting internal to host: $rex->[host_]";
	$rex->[session_]->server->current_cb->(
		$rex->[host_],			#Internal redirects are to same host
		join(" ", $rex->@[method_, uri_]),#New method and url
		$rex,				#Same rex
		$code,$headers			#New code and headers
	);
	1;
}

sub rex_headers {
	return $_[1]->[headers_];
}

sub rex_reply_json {
	my $data=pop;
	Log::OK::DEBUG and log_debug "rex_reply_json caller: ". join ", ", caller;
	rex_write @_, HTTP_OK, [
		HTTP_CONTENT_TYPE, "text/json",
		HTTP_CONTENT_LENGTH, length($data),
	], $data;
}

sub rex_reply_html {
	my $data=pop;
	rex_write @_, HTTP_OK, [
		HTTP_CONTENT_TYPE, "text/html",
		HTTP_CONTENT_LENGTH, length($data),
	], $data;
}
sub rex_reply_javascript {
	my $data=pop;
	rex_write @_, HTTP_OK, [
		HTTP_CONTENT_TYPE, "text/javascript",
		HTTP_CONTENT_LENGTH, length($data),
	], $data;
}

sub rex_reply_text {
	my $data=pop;
	rex_write @_, HTTP_OK, [
		HTTP_CONTENT_TYPE, "text/plain",
		HTTP_CONTENT_LENGTH, length($data),
	], $data;
}

sub rex_captures {
	$_[1][captures_]
}


#returns parsed cookies from headers
#Only parses if the internal field is undefined
#otherwise uses pre parsed values
#Read only
sub cookies :lvalue {
	$_[0][cookies_]//($_[0][cookies_]=parse_cookie $_[0][headers_]{COOKIE});
}

#RW accessor
#Returns the current state information for the rex
sub state :lvalue { $_[0][state_] }
sub captures:lvalue { $_[0][captures_] }
sub writer {
	$_[0][write_];

}
	


my $id=0;	#Instead of using state
my $_i;
sub new {
	#my ($package, $session, $headers, $host, $version, $method, $uri, $ex)=@_;
	#	0	1	  2	    3		4	5	6   7

	#state $id=0;
	my $query_string="";
	$query_string=substr($_[6], $_i+1)
		if(($_i=index($_[6], "?"))>=0);
	
	Log::OK::DEBUG and log_debug "+++++++Create rex: $id";

	#my $write=undef;

	my $self=bless [ $_[4], $_[1], $_[2], undef, undef, $query_string, 1 ,undef,undef,undef,$_[3], $_[5], $_[6], $_[6], {}, [],[],[],[],[], $id++], $_[0];

	#my $write=$_[1]->[uSAC::HTTP::Session::write_];
	#
	#NOTE: A single call to Session export. give references to important variables
	
	($self->[closeme_], $self->[dropper_], $self->[server_], $self->[rex_], $self->[in_progress_], $self->[write_])= $_[7]->@*;#$_[1]->exports->@*;
	$self->[recursion_count_]=0;

	$self;
}


#multipart for type.
#Sub parts can be of different types and possible content encodings?
sub usac_multipart_stream {
		my $cb=pop;
		sub {
			my $line=$_[0];#shift;
			my $rex=$_[1];#shift;
			#shift;		#remove place holder for mime
			my $session=$rex->[uSAC::HTTP::Rex::session_];
			#check if content type is correct first
			unless (index($rex->[headers_]{CONTENT_TYPE},'multipart/form-data')>=0){
				#$session->[uSAC::HTTP::Session::closeme_]=1;
				$rex->[closeme_]->$*=1;

				rex_write $line,$rex, HTTP_UNSUPPORTED_MEDIA_TYPE,[] ,"multipart/formdata required";
				return;
			}
			#uSAC::HTTP::Session::push_reader
			
			$session->push_reader(
				make_form_data_reader @_, $session, $cb->()
			);

			Log::OK::INFO and log_info "multipart stream";
			#$_[1][session_][uSAC::HTTP::Session::in_progress_]=1;
			$_[1][in_progress_]->$*=1;

			$session->pump_reader;
			return;
		}
}

#reads a post/put request
#handles HTTP/1.1 continue
#checks mime types are as specified (any type is default)
#runs callback with parts of data
#
sub usac_data_stream{

	my $cb=pop;	#cb for parts
	my %options=@_;
	my $mime=$options{mime}//".*";	#application/x-www-form-urlencoded';
	my $upload_limit=$options{byte_limit}//$UPLOAD_LIMIT;

	sub {
		#my $line=shift;
		my $matcher=$_[0];
		my $rex=$_[1];#shift;	#rex object

		my $session=$rex->[session_];
		my @err_res;
		for($rex->[headers_]){
			#Wrap regex to prevent captures being destroyed
			if($_->{CONTENT_TYPE}!~/$mime/){
				@err_res=(HTTP_UNSUPPORTED_MEDIA_TYPE, [], "Must match $mime");
			}

			elsif(defined $upload_limit  and $_->{CONTENT_LENGTH} > $upload_limit){
				@err_res=(HTTP_PAYLOAD_TOO_LARGE, [], "limit: $upload_limit");
			}

			else{

				#uSAC::HTTP::Session::push_reader
				$session->push_reader(
					make_form_urlencoded_reader @_, $session, $cb->()
				);

				#check for expects header and send 100 before trying to read
				if(defined($_->{EXPECT})){
					#issue a continue response	
					my $reply= "HTTP/1.1 ".HTTP_CONTINUE.LF.LF;
					$rex->[uSAC::HTTP::Rex::write_]->($reply);
				}

				Log::OK::INFO and log_info "data stream";
				#$_[1][session_][uSAC::HTTP::Session::in_progress_]=1;
				$_[1][in_progress_]->$*=1;

				$session->pump_reader;
				return;
			}
		}

		#$session->[uSAC::HTTP::Session::closeme_]=1;
		$_[1][closeme_]->$*=1;
		rex_write @_, @err_res;#$line,$rex,@err_res; 
	}
}

sub usac_urlencoded_stream {
	my $cb=pop;
	my %options=@_;
	$options{mime}="application/x-www-form-urlencoded";
	usac_data_stream %options, $cb;
}

#uses handle_upload or  usac_multipart_stream setup for
#html forms
sub usac_form_stream {
	#my ($cb)=@_;
	my $multi=  usac_multipart_stream @_;
	my $url= usac_urlencoded_stream @_;
	sub{
		for ($_[1][headers_]{CONTENT_TYPE}){
			&$multi  and return if /multipart\/form-data/;
			&$url  and return if 'application/x-www-form-urlencoded';
			rex_write $_[0],$_[1], HTTP_UNSUPPORTED_MEDIA_TYPE,[] ,"multipart/form-data or application/x-www-form-urlencoded required";
		}
	}
}

#process urlencoded form
#Return a set of kv pairs
#Last item is $cb
sub usac_urlencoded_slurp{
	my $cb=pop;
	#The actual sub called
	#Expected inputs
	#	line, rex, data, part header, completeflag
	usac_urlencoded_stream sub {

		sub {
			my $usac=$_[0];
			my $rex=$_[1];
			my $code=$_[2];
			my $head=$_[3];

			state $part_header=0;
			state $fields={};

			if($part_header != $_[3]){
				#new part
				local $,=", ";
				$part_header=$_[3];
				$fields=&parse_form_params;

				#test for file
			}

			if($_[4]){
				#that was the last part
				$cb->($usac, $rex, $code, $head, $fields,1);
				$part_header=0;
				$fields={};	#reset 
			}
		}
	}

}

#Writes any file attachments to temp files 
#NOTE only form-data/multipart
sub usac_multipart_slurp{
	my $cb=pop;
	my %options=@_;
        my $tmp_dir=$options{dir}//"uploads";	#temp dir to save file to

	$tmp_dir=uSAC::HTTP::Site::usac_path(%options, $tmp_dir);

	#Attempt open the dir or die
	die "Could not open directory $tmp_dir for uploads",unless opendir((my $fh), $tmp_dir);
        my $prefix=$options{prefix}//"uSAC";
	#The actual sub called
	usac_multipart_stream sub {
		sub {
			my $usac=$_[0];
			my $rex=$_[1];
			my $code=$_[2];
			my $head=$_[3];
			state $part_header=0;

			state $kv;		#Stateful for multiple calls
			state $fields={};	#

			state ($handle,$name);
			if($part_header != $_[3]){
				#new part
				local $,=", ";
				$part_header=$_[3];
				close $handle if $handle;
				$name=$handle=undef;
				{
					$kv=&parse_form_params;
				}

				#test for file
				if($kv->{filename}){
					#this is a file
					#open an file
					($handle, $name)=tempfile($prefix. ("X"x10), DIR=>$tmp_dir);
					$fields->{$kv->{name}}={tmp_file=>$name, filename=>$kv->{filename}, CONTENT_TYPE=>$part_header->{CONTENT_TYPE}};
				}
				else {
					#just a regular form field
					$fields->{$kv->{name}}=$_[2];
				}
			}

			#write to file only if its a file
			my $wc=syswrite $handle, $_[2] if $handle;
			if($_[4]){
				#that was the last part
				$cb->($usac, $rex, $code, $head, $fields,1);
				$part_header=0;
				$fields={};	#Reset after callback
				$kv={};		#Reset after callback
			}
		}
	}
}

#Handles either multipart or urlencoded body forms
#Callback is last argument and is called  on complete upload of all data
#Expected inputs to sub ref:
#line, rex, data, part header, completeflag
sub usac_form_slurp{
	my ($cb)=pop;
	my %options=@_;
	Log::OK::TRACE and  log_trace "Setup usac_form_slurp";
	my $tmp_dir=$options{dir}//"uploads";

	#$tmp_dir=uSAC::HTTP::Site::usac_path(%options, $tmp_dir);
	#convert to abs path to prevent double resolving
	unless( -d $tmp_dir){
		my $message= "Could not access directory $tmp_dir for uploads. Does it exist?";
		Log::OK::FATAL and log_fatal $message;
		die $message;
	}

	$options{dir}=rel2abs($tmp_dir);
	
	my $multi= usac_multipart_slurp %options, $cb;
	my $url=usac_urlencoded_slurp %options, $cb;
	sub{
		for ($_[1][headers_]{CONTENT_TYPE}){
			if(index($_, "multipart/form-data")>=0){
				#we do a regex match inste
				&$multi;
				return
			}
			elsif($_ eq 'application/x-www-form-urlencoded'){
				&$url;
				return
			}
			else{
				rex_write $_[0],$_[1], HTTP_UNSUPPORTED_MEDIA_TYPE,[] ,"multipart/form-data or application/x-www-form-urlencoded required";
			}
		}
	}
}
#Returns a sub which writes the streaming data to file. Callback is called when file is
#completely downloaded
#
sub usac_data_slurp{
	my $cb=pop;
	my %options=@_;


        my $tmp_dir=$options{dir};#//"uploads";	#temp dir to save file to

	#$tmp_dir=uSAC::HTTP::Site::usac_path(%options, $tmp_dir);

        my $prefix=$options{prefix}//"uSAC";
	die "Could not access directory $tmp_dir for file uploads" if $tmp_dir and ! -d $tmp_dir;
	#my $mime=$options{mime};#//"application/x-www-form-urlencoded";
	my $path=$options{path};

	make_path $tmp_dir unless $path;

	usac_data_stream %options, sub {
		Log::OK::INFO and log_info "wrapper...";
		sub {
			my $matcher=$_[0];
			my $rex=$_[1];
			my $code=$_[2];
			my $head=$_[3];
			state $header=0;
			state ($handle, $name);
			state $mem="";
			my $wc;
			if( $header != $_[3]){
				#first chunk 
				$header=$_[3];
				close $handle if $handle;
				$handle=undef;
				if($path){
					unless(open $handle, ">", $path){

						Log::OK::INFO and log_info "Opening file";
						rex_error_internal_server_error $matcher, $rex;
					}
					$name=(split "/", $path)[-1];
				}
				elsif($tmp_dir){
					try{
						($handle, $name)=tempfile($prefix. ("X"x10), DIR=>$tmp_dir);
					}
					catch {
						rex_error_internal_server_error $matcher, $rex;

					};
				}
				else {
					Log::OK::INFO and log_info "Opening memory";

				}
			}
			if($path or $tmp_dir){
				$wc=syswrite $handle, $_[2];
				unless($wc){
					rex_error_internal_server_error $matcher, $rex;
				}

			}
			else {
				$mem.=$_[2];
			}
			#TODO: error checking and drop connection on write error
			if($_[4]){
				unless($path or $tmp_dir){
					$cb->($matcher, $rex, $code, $head, $mem,1)
				}
				else {
					$cb->($matcher, $rex, $code, $head, $name,1)
				}
				$mem="";
				$header=0;
				$name=undef;
				$handle=undef;
			}

			#}
		}
	}
	
}

#parse a form in either form-data or urlencoded.
#First arg is rex
#second is data
#third is the header for each part if applicable
sub parse_form_params {
	my $rex=$_[1];
	#0=>line
	#1=>rex
	#2=>data
	#3=>section header
	#
	#parse the fields	
	for ($rex->[headers_]{CONTENT_TYPE}){
		if(/multipart\/form-data/){
			#parse content disposition (name, filename etc)
			my $kv={};
			for(map tr/ //dr, split ";", $_[3]->{CONTENT_DISPOSITION}){
				my ($key, $value)=split "=";
				$kv->{$key}=defined($value)?$value=~tr/"//dr : undef;
			}
			return $kv;
		}
		elsif($_ eq 'application/x-www-form-urlencoded'){
			my $kv={};
			for(split "&", uri_decode_utf8 $_[2]){
				my ($key,$value)=split "=";
				$kv->{$key}=$value;
			}
			return $kv;
		}

		else{
			return {};
		}

	}
}

#Parse the query
sub parse_query_params_old {
	my $rex=shift;
	#NOTE: This should already be decoded so no double decode
	my $kv={};
	for(map tr/ //dr, split "&", $rex->[query_string_]){
		my ($key,$value)=split "=";
		$kv->{$key}=$value;

	}
	return $kv;
}

##############################################################################################################################
# sub DESTROY {                                                                                                              #
#         Log::OK::DEBUG and log_debug "+++++++Destroy rex: $_[0][id_],  session $_[0][session_][uSAC::HTTP::Session::id_]"; #
# }                                                                                                                          #
##############################################################################################################################
#binary data.
# might have contetn-encoding apply however ie base64, gzip

#content type text/plain with optional charset spec
#also setup need to decode any Content-Encoding (ie gzip)



	 

*rex_parse_form_params=*parse_form_params;
*rex_query_params=*query_params;


1;
