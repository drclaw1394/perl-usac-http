#package AnyEvent::HTTP::Server::Form;

package uSAC::HTTP::Rex;
use version; our $VERSION = version->declare('v0.1');
use common::sense;
use feature qw<refaliasing switch state>;
our $UPLOAD_LIMIT=10_000_000;

use uSAC::HTTP::Code qw<:constants>;
use uSAC::HTTP::Header qw<:constants>;
#use uSAC::HTTP::Server;
use constant LF => "\015\012";


use uSAC::HTTP::Session;
#use uSAC::HTTP::Server;
use uSAC::HTTP::Cookie qw<:all>;

use AnyEvent;
use Exporter 'import';
use File::Temp qw<tempfile>;
use File::Path qw<make_path>;

our @EXPORT_OK=qw<rex_headers rex_reply rex_reply_simple rex_reply_chunked static_content rex_form_upload rex_urlencoded_upload rex_handle_upload rex_handle_multipart_upload rex_handle_form_upload rex_handle_urlencoded_upload rex_upload_to_file rex_save_to_file rex_parse_form_params rex_parse_query_params>;
our @EXPORT=@EXPORT_OK;




use Time::HiRes qw/gettimeofday/;
use Scalar::Util qw(weaken);
use Encode qw<decode encode decode_utf8>;


#Class attribute keys
#method_ uri_
#ctx_ reqcount_ 
use enum (
	"version_=0" ,qw< session_ headers_ write_ query_ server_ time_ cookies_ handle_ attrs_ host_ method_ uri_stripped_ uri_ static_headers_ >
);

#Add a mechanism for sub classing
use constant KEY_OFFSET=>0;
use constant KEY_COUNT=>static_headers_-version_+1;

sub uri_decode {
	my $octets= shift;
	$octets=~ s/\+/ /sg;
	$octets=~ s/%([[:xdigit:]]{2})/chr(hex($1))/ge;
	return decode_utf8($octets);
	#return decode("utf8", $octets);
}
		
sub reply_simple;
		
	

sub reply_GZIP {

}

#like simple reply but does a DEFLATE on the data.
#Sets the headers accordingly
sub reply_DEFLATE {
	#call replySimple with extra headers
}


#multipart for type.
#Sub parts can be of different types and possible content encodings?
sub handle_multipart_upload {
		my $cb=shift;
	sub {
		my $line=shift;
		my $rex=shift;
		shift;		#remove place holder for mime
		my $session=$rex->[uSAC::HTTP::Rex::session_];
		#check if content type is correct first
		say "CONTENT TYPE ON UPLOAD: ", $rex->[headers_]{'CONTENT_TYPE'};
		unless (index($rex->[headers_]{'CONTENT_TYPE'},'multipart/form-data')>=0){
			$session->[uSAC::HTTP::Session::closeme_]=1;
			reply_simple $line,$rex, HTTP_UNSUPPORTED_MEDIA_TYPE,[] ,"multipart/formdata required";
			return;
		}
		uSAC::HTTP::Session::push_reader
		$session,
		"http1_1_form_data",

		$cb
		;
		$session->[uSAC::HTTP::Session::read_]->(\$session->[uSAC::HTTP::Session::rbuf_],$rex);
	}
}

#reads a post/put request
#handles HTTP/1.1 continue
#checks mime types are as specified (any type is default)
#runs callback with parts of data
#
sub handle_upload {
	my $mime=shift//".*";#application/x-www-form-urlencoded';
	my $upload_limit=$UPLOAD_LIMIT;
	my $cb=shift;	#cb for parts

	sub {
	my $line=shift;
	my $rex=shift;	#rex object


	my $session=$rex->[session_];
	say "CONTENT TYPE ON UPLOAD:", $rex->[headers_]{'CONTENT_TYPE'};
	say $mime;
	my @err_res;
	given($rex->[headers_]){
		when($_->{'CONTENT_TYPE'}!~/$mime/){
			@err_res=(HTTP_UNSUPPORTED_MEDIA_TYPE, [], "Must match $mime");
		}
		when($_->{'CONTENT_LENGTH'} > $upload_limit){
			@err_res=(HTTP_PAYLOAD_TOO_LARGE, [], "limit: $UPLOAD_LIMIT");
		}
		default{

			uSAC::HTTP::Session::push_reader
			$session,
			"http1_1_urlencoded",
			$cb
			;

			#check for expects header and send 100 before trying to read
			#given($rex->[uSAC::HTTP::Rex::headers_]){
			if(defined($_->{EXPECTS})){
				#issue a continue response	
				my $reply= "HTTP/1.1 ".HTTP_CONTINUE.LF.LF;
				$rex->[uSAC::HTTP::Rex::write_]->($reply);
			}

			$session->[uSAC::HTTP::Session::read_]->(\$session->[uSAC::HTTP::Session::rbuf_],$rex);
			return;
		}
	}

	$session->[uSAC::HTTP::Session::closeme_]=1;
	reply_simple $line,$rex,@err_res; 
}
}
sub handle_urlencoded_upload {
	handle_upload "application/x-www-form-urlencoded", shift;
}

#uses handle_upload or handle_multipart_upload setup for
#html forms
sub handle_form_upload {
	my ($cb)=@_;
	my $multi=handle_multipart_upload @_;
	my $url=handle_urlencoded_upload @_;
	sub{
		given ($_[1][headers_]{CONTENT_TYPE}){
			&$multi when /multipart\/form-data/;
			&$url when 'application/x-www-form-urlencoded';
			default {
				reply_simple undef,$_[1], HTTP_UNSUPPORTED_MEDIA_TYPE,[] ,"multipart/form-data or application/x-www-form-urlencoded required";
			}
		}
	}
}

#Returns a sub which writes the streaming data to file. Callback is called when file is
#completely downloaded
#
sub save_to_file {
	my $cb=pop;
	my %options=@_;
	
        my $tmp_dir=$options{dir}//"uploads";	#temp dir to save file to
        my $prefix=$options{prefix}//"uSAC";
	my $mime=$options{mime};#//"application/x-www-form-urlencoded";
	my $path=$options{path};

	make_path $tmp_dir unless $path;

	handle_upload $mime, sub {
		my $rex=$_[1];
		#handle_upload @_, $mime, sub {
			state $header=0;
			state ($handle, $name);
			my $wc;
			if( $header != $_[1]){
				#first chunk 
				$header=$_[1];
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
			$wc=syswrite $handle, $_[0];
			#TODO: error checking and drop connection on write error
			if($_[2]){
				$header=0;
				$cb->(undef, $rex, $name,1);
			}

			#}
	}
	
}

#parse a form in either form-data or urlencoded.
#First arg is rex
#second is data
#third is the header for each part if applicable
sub parse_form_params {
	my $rex=shift;
	#0=>rex
	#1=>data
	#2=>section header
	#
	#parse the fields	
	given($rex->[headers_]{CONTENT_TYPE}){
		when(/multipart\/form-data/){
			#parse content disposition (name, filename etc)
			my $kv={};
			for(map tr/ //dr, split ";", $_[1]->{CONTENT_DISPOSITION}){
				my ($key, $value)=split "=";
				$kv->{$key}=$value;
			}
			return $kv;
		}
		when('application/x-www-form-urlencoded'){
			my $kv={};
			for(split "&", uri_decode $_[0]){
				my ($key,$value)=split "=";
				$kv->{$key}=$value;
			}
			return $kv;
		}

		default {
			return {};
		}

	}
}

#Parse the query
sub parse_query_params {
	my $rex=shift;
	#NOTE: This should already be decoded so no double decode
	my $kv={};
	if(my $i=index($rex->[uri_],"?")){
		for(map tr/ //dr,split "&", substr($rex->[uri_],$i+1)){
			my ($key,$value)=split "=";
			$kv->{$key}=$value;

		}
	}
	return $kv;
}

#binary data.
# might have contetn-encoding apply however ie base64, gzip

#content type text/plain with optional charset spec
#also setup need to decode any Content-Encoding (ie gzip)


#Reply the body and code specified. Adds Server and Content-Length headers
#Line, Rex, code, header_ref, content

sub reply_simple{
	use integer;
	my ($line, $self)=@_;
	#create a writer for the session
	my $session=$self->[session_];
	\my $reply=\$session->[uSAC::HTTP::Session::wbuf_];
	#my $content_length=length($_[4])+0;
	my $headers=[
		[HTTP_DATE,		$uSAC::HTTP::Session::Date],
		[HTTP_CONTENT_LENGTH,	length ($_[4])+0],
		($session->[uSAC::HTTP::Session::closeme_]
			?[HTTP_CONNECTION,	"close"]
			:([	HTTP_CONNECTION,	"Keep-Alive"],
				[HTTP_KEEP_ALIVE,	"timeout=10, max=1000"]
			)
		)

	];

	$reply="HTTP/1.1 $_[2]".LF;
	for my $h ($self->[static_headers_]->@*, $headers->@*, ($_[3]//[])->@*){
		$reply.=$h->[0].": ".$h->[1].LF;
	}
	$reply.=LF.$_[4];
	$self->[write_]($reply);	#fire and forget
}

#rex, http_code, header, datacb 
sub reply_chunked{
	use integer;
	my (undef, $self, $code, $headers, $cb)=@_;
	#create a writer for the session
	my $session=$self->[session_];
	\my $reply=\$session->[uSAC::HTTP::Session::wbuf_];

	#my $content_length=length($_[4])+0;
	$reply= "HTTP/1.1 $code".LF;
	my $headers=[
		[HTTP_DATE,		$uSAC::HTTP::Session::Date],
		($session->[uSAC::HTTP::Session::closeme_]
			?[HTTP_CONNECTION,	"close"]
			:(	[HTTP_CONNECTION,	"Keep-Alive"],
				[HTTP_KEEP_ALIVE,	"timeout=10, max=1000"]
			)
		),
		[HTTP_TRANSFER_ENCODING, "chunked"]

	];
	#render_v1_1_headers($reply, $headers, $self->[static_headers_], $_[3]);
	for my $h ($self->[static_headers_]->@*, $headers->@*, ($_[3]//[])->@*){
		$reply.=$h->[0].": ".$h->[1].LF;
	}
	$reply.=LF;


	my $chunker=uSAC::HTTP::Session::select_writer $session, "http1_1_chunked_writer";	
	#write the header, and then do callback to let app write data
	#use chunker as argument which will be first argument of callback
	$self->[write_]($reply, $cb, $chunker);
}

sub reply {
	#wrapper for simple and chunked
	# if the body element is a code ref, or array ref, then chunked is used
	given(ref $_[4]){
		reply_chunked @_ when "CODE";
		when("ARRAY"){
			#send each element of array as a chunk
			my $i=0;
			my $chunks=pop;
			#push @$chunks, "";

			reply_chunked @_ ,sub {
				$_[0]->($chunks->[$i++], $i != $chunks->@* ? __SUB__:undef);
			};
		}
		default {
			reply_simple @_;
		}
	}
}

#returns a sub which always renders the same content.
#http code is always
sub static_content {
	my $static=pop;	#Content is the last item
	my $ext=$_[0]//"txt";
	my $headers=
	[[HTTP_CONTENT_TYPE, ($uSAC::HTTP::Server::MIME{$ext}//$uSAC::HTTP::Server::DEFAULT_MIME)]];
	sub {
		reply_simple @_, HTTP_OK, $headers, $static; return
	}
}


sub render_v1_1_headers_flat {
	use integer;
	\my $buffer=\shift;#$_[0];
	my $i;
	for(@_){
		$i=0;
		\my @headers=$_//[];
		while($i<@headers){
			$buffer.=$headers[$i++].": ".$headers[$i++].LF;
		}
	}
}
sub render_v1_1_headers_multi {
	\my $buffer=\shift;#$_[0];
	for(@_){
		for my $h (@$_){
			$buffer.=$h->[0].": ".$h->[1].LF;
		}
	}
}
sub render_v1_1_headers {
	\my $buffer=\shift;#$_[0];
	for my $h (@_){
		$buffer.=$h->[0].": ".$h->[1].LF;
	}
}
	 
##
#OO Methods
#

# Returns the headers parsed at connection time
sub headers {
	return $_[0]->[headers_];
}

#Returns parsed query parameters. If they don't exist, they are parse first
sub query {
	$_[0][query_]//($_[0][query_]=parse_query_params @_);
}

#returns parsed cookies from headers
#Only parses if the internal field is undefined
#otherwise uses pre parsed values
sub cookies {
	$_[0][cookies_]//($_[0][cookies_]=parse_cookie $_[0][headers_]{COOKIE});
}

*rex_headers=*headers;
*rex_reply_simple=*reply_simple;
*rex_reply_chunked=*reply_chunked;
*rex_reply=*reply;
*rex_urlencoded_upload=*handle_urlencode_upload;
*rex_handle_upload=*handle_upload;
*rex_handle_multipart_upload=*handle_multipart_upload;
*rex_handle_urlencoded_upload=*handle_urlencoded_upload;
*rex_handle_form_upload=*handle_form_upload;
*rex_parse_form_params=*parse_form_params;
*rex_parse_query_params=*parse_query_params;
*rex_save_to_file=*save_to_file;

1;
