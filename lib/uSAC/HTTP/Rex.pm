package uSAC::HTTP::Rex;
use warnings;
use strict;
use version; our $VERSION = version->declare('v0.1');
use feature qw<current_sub say refaliasing switch state>;
no warnings "experimental";
our $UPLOAD_LIMIT=10_000_000;

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
rex_error_internal 

rex_redirect_internal

rex_reply_json
rex_reply_html
rex_reply_javascript
rex_reply_text

rex_capture
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
	"version_=0" ,qw< session_ headers_ write_ query_ query_string_ time_ cookies_ handle_ attrs_ host_ method_ uri_stripped_ uri_ state_ capture_>
);

#Add a mechanism for sub classing
use constant KEY_OFFSET=>0;
use constant KEY_COUNT=>capture_-version_+1;

require uSAC::HTTP::Middleware;
###########################################################
# sub uri_decode {                                        #
#         my $octets= shift;                              #
#         $octets=~ s/\+/ /sg;                            #
#         $octets=~ s/%([[:xdigit:]]{2})/chr(hex($1))/ge; #
#         return decode_utf8($octets);                    #
#         #return decode("utf8", $octets);                #
# }                                                       #
# sub uri_decode_inplace {                                #
#         $_[0]=~ s/\+/ /sg;                              #
#         $_[0]=~ s/%([[:xdigit:]]{2})/chr(hex($1))/ge;   #
#         decode_utf8($_[0]);                             #
#         #return decode("utf8", $octets);                #
# }                                                       #
###########################################################
		
sub rex_write;		
	


sub new {
	#my ($package, $session, $headers, $version, $method, $uri)=@_;

	my $self=[];
	my $query_string="";
	if((my $i=index($_[5], "?"))>=0){
		$query_string=substr $_[5], $i+1;
	}
	my $write=$_[1]->[uSAC::HTTP::Session::write_];

	bless [ $_[3], $_[1], $_[2], $write, undef, $query_string, 1 ,undef,undef,undef,$_[2]{HOST}, $_[4], $_[5], $_[5], {}, []], $_[0];


}

sub reply_GZIP {

}

#like simple reply but does a DEFLATE on the data.
#Sets the headers accordingly
sub reply_DEFLATE {
	#call replySimple with extra headers
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
			$session->[uSAC::HTTP::Session::closeme_]=1;
			rex_write $line,$rex, HTTP_UNSUPPORTED_MEDIA_TYPE,[] ,"multipart/formdata required";
			return;
		}
		uSAC::HTTP::Session::push_reader
		$session,
		make_form_data_reader @_, $session, $cb ;
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

				uSAC::HTTP::Session::push_reader
				$session,
				make_form_urlencoded_reader @_, $session, $cb ;

				#check for expects header and send 100 before trying to read
				if(defined($_->{EXPECT})){
					#issue a continue response	
					my $reply= "HTTP/1.1 ".HTTP_CONTINUE.LF.LF;
					$rex->[uSAC::HTTP::Rex::write_]->($reply);
				}
				$session->pump_reader;
				return;
			}
		}

		$session->[uSAC::HTTP::Session::closeme_]=1;
		rex_write @_, @err_res;#$line,$rex,@err_res; 
	}
}

sub usac_urlencoded_stream {
	my $cb=pop;;
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
		my $usac=$_[0];
		my $rex=$_[1];
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
			$cb->($usac, $rex, $fields,1);
			$part_header=0;
			$fields={};	#reset 
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
		my $usac=$_[0];
		my $rex=$_[1];
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
			$cb->($usac, $rex, $fields,1);
			$part_header=0;
			$fields={};	#Reset after callback
			$kv={};		#Reset after callback
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
	say "Setup form slurp";
	my $tmp_dir=$options{dir}//"uploads";

	$tmp_dir=uSAC::HTTP::Site::usac_path(%options, $tmp_dir);
	#convert to abs path to prevent double resolving
	die "Could not access directory $tmp_dir for uploads" unless -d $tmp_dir;
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


        my $tmp_dir=$options{dir}//"uploads";	#temp dir to save file to

	$tmp_dir=uSAC::HTTP::Site::usac_path(%options, $tmp_dir);

        my $prefix=$options{prefix}//"uSAC";
	die "Could not access directory $tmp_dir for uploads",unless -d $tmp_dir;
	my $mime=$options{mime};#//"application/x-www-form-urlencoded";
	my $path=$options{path};

	make_path $tmp_dir unless $path;

	usac_data_stream %options, sub {
		my $rex=$_[1];
		#handle_upload @_, $mime, sub {
			state $header=0;
			state ($handle, $name);
			my $wc;
			if( $header != $_[3]){
				#first chunk 
				$header=$_[3];
				close $handle if $handle;
				$handle=undef;
				if($path){
					open $handle, ">", $path;
					$name=(split "/", $path)[-1];
				}
				else{
					($handle, $name)=tempfile($prefix. ("X"x10), DIR=>$tmp_dir);
				}
			}
			$wc=syswrite $handle, $_[2];
			#TODO: error checking and drop connection on write error
			if($_[4]){
				$cb->(undef, $rex, $name,1);
				$header=0;
				$name=undef;
				$handle=undef;
				
			}

			#}
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
			for(split "&", uri_decode $_[2]){
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


#binary data.
# might have contetn-encoding apply however ie base64, gzip

#content type text/plain with optional charset spec
#also setup need to decode any Content-Encoding (ie gzip)



#Main output subroutine
#Arguments are matcher, rex, code, header, data, cb
sub rex_write{
	my $session=$_[1]->[session_];
	if($_[3]){
		#If headers are supplied, then  process headers
		$session->[uSAC::HTTP::Session::in_progress_]=1;
		\my @h=$_[3];

		if($session->[uSAC::HTTP::Session::closeme_]){
			push @h, 
				HTTP_CONNECTION, "close";
		}
		else{
			push @h,
				HTTP_CONNECTION, "keep-alive",
				HTTP_KEEP_ALIVE,"timeout=10, max=1000";
		}

		state $server=$session->[uSAC::HTTP::Session::server_];
		state $static_headers=$server->static_headers;

		if($server!=$session->[uSAC::HTTP::Session::server_]){
			$server=$session->[uSAC::HTTP::Session::server_];
			state $static_headers=$server->static_headers;
		}
		push @h,
			$static_headers->@*,
			HTTP_DATE, $uSAC::HTTP::Session::Date;
	}

	#Otherwise this is just a body call
	#

	&{$_[0][4][1]};	#Execute the outerware for this site/location
	1;
}
	 
##
#OO Methods
#

#actually render the header 
my @index=map {$_*2} 0..99;
sub render_header {
	my $self=shift;
	no warnings "uninitialized";
	#my ($matcher, $rex, $code, $headers, $data)=@_;
		
	my $session=$self->[session_];

	$session->[uSAC::HTTP::Session::in_progress_]=1;


	my $reply="HTTP/1.1 $_[2]".LF;
	\my @h=$_[3];
	#$reply.= join "", map $_.": ".$h{$_}.LF, keys $_[3]->%*;

	
	for(@index){
		last unless $h[$_];
		$reply.= "$h[$_]: $h[$_+1]".LF;
	}
	#$reply.=join "", map {$h[$_]?("$h[$_]: $h[$_+1]".LF):()} @index;
	#say $reply;
	#0..@h/2-1;
	#$reply.=join "", map {my $a=2*$_;"$h[$a]: $h[$a+1]".LF} 0..@h/2-1;
	#$reply.=join "", map "$h[2*$_]: $h[2*$_+1]".LF, 0..@h/2-1;

	$reply.=LF;
}

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
	my $url= $_[0][4][0]->built_prefix;
	if($_[2]//""){
		return "$url/$_[2]";
	}
	$url;
	#$_[0][4][0]->built_prefix."/".($_[3]//"");
}

#returns the site object associate with this request
#match, rex, na
sub rex_site {
	$_[0][4][0];	
}

sub rex_state :lvalue{
	$_[1][state_];
}

#redirect to within site
#match entry
#rex
#partial url
#code
sub rex_redirect_see_other{
	my ($url)=splice @_, 2;
	rex_write (@_, HTTP_SEE_OTHER,[HTTP_LOCATION,$url, HTTP_CONTENT_LENGTH, 0],"");
}

sub rex_redirect_found {
	my ($url)=splice @_, 2;
	rex_write (@_, HTTP_FOUND,[HTTP_LOCATION, $url, HTTP_CONTENT_LENGTH, 0],"");
	
}

sub rex_redirect_temporary {

	my ($url)=splice @_, 2;
	rex_write (@_, HTTP_TEMPORARY_REDIRECT,[HTTP_LOCATION, $url, HTTP_CONTENT_LENGTH, 0],"");
	
}
sub rex_redirect_not_modified {
	my ($url)=splice @_, 2;
	rex_write (@_, HTTP_NOT_MODIFIED,[HTTP_LOCATION, $url, HTTP_CONTENT_LENGTH, 0],"");
	
}

sub rex_error_not_found {
	my ($url)=splice @_, 2;
	rex_write (@_, HTTP_NOT_FOUND, [HTTP_CONTENT_LENGTH, 0], '');
}

sub rex_error_internal {
	my ($url)=splice @_, 2;
	my $session=$_[1][session_];
	rex_write (@_, HTTP_INTERNAL_SERVER_ERROR, [HTTP_CONTENT_LENGTH, 0], '');
	$session->[uSAC::HTTP::Session::closeme_]=1;
	$session->[uSAC::HTTP::Session::dropper_]->();
}


#Rewrites the uri and matches through the dispatcher
#TODO: recursion limit
sub rex_redirect_internal {

	my ($matcher, $rex, $uri)=@_;
	state $previous_rex=$rex;
	state $counter=0;
	if(substr($uri,0,1) ne "/"){
		$uri="/".$uri;	
	}
	$rex->[uri_]=$uri;
	$rex->[uri_stripped_]=$uri;
	if($rex==$previous_rex){
		$counter++;
	}
	else {
		$previous_rex=$rex;
	}
	if($counter>10){
		$counter=0;
		carp "Redirections loop detected for $uri";
		rex_write($matcher, $rex, HTTP_LOOP_DETECTED, [],"");
		return;
	}
	undef $_[0];
	$rex->[session_]->server->current_cb->(
		join(" ", $rex->@[host_, method_, uri_]),
		$rex
	);
	1;
}
sub rex_headers {
	return $_[1]->[headers_];
}

sub rex_reply_json {
	my $data=pop;
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
sub rex_capture {
	$_[1][capture_]
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
sub capture:lvalue { $_[0][capture_] }
sub writer {
	$_[0][write_];

}

*rex_parse_form_params=*parse_form_params;
*rex_query_params=*query_params;


1;
