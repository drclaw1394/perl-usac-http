#package AnyEvent::HTTP::Server::Form;

package uSAC::HTTP::Rex;
use version; our $VERSION = version->declare('v0.1');
use feature qw<current_sub say refaliasing switch state>;
no warnings "experimental";
our $UPLOAD_LIMIT=10_000_000;


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

our @EXPORT_OK=qw<rex_headers rex_reply rex_reply_simple rex_reply_chunked rex_form_upload rex_urlencoded_upload rex_handle_upload rex_stream_multipart_upload rex_stream_form_upload rex_stream_urlencoded_upload rex_upload_to_file rex_save_to_file rex_save_form_to_file rex_save_form rex_save_web_form rex_parse_form_params rex_query_params>;
our @EXPORT=@EXPORT_OK;




use Time::HiRes qw/gettimeofday/;
use Scalar::Util qw(weaken);
use Encode qw<decode encode decode_utf8>;


#Class attribute keys
#method_ uri_
#ctx_ reqcount_ 
use enum (
	"version_=0" ,qw< session_ headers_ write_ query_ query_string_ server_ time_ cookies_ handle_ attrs_ host_ method_ uri_stripped_ uri_ state_ static_headers_ >
);

#Add a mechanism for sub classing
use constant KEY_OFFSET=>0;
use constant KEY_COUNT=>static_headers_-version_+1;

require uSAC::HTTP::Middleware;
sub uri_decode {
	my $octets= shift;
	$octets=~ s/\+/ /sg;
	$octets=~ s/%([[:xdigit:]]{2})/chr(hex($1))/ge;
	return decode_utf8($octets);
	#return decode("utf8", $octets);
}
sub uri_decode_inplace {
	$_[0]=~ s/\+/ /sg;
	$_[0]=~ s/%([[:xdigit:]]{2})/chr(hex($1))/ge;
	decode_utf8($_[0]);
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
sub stream_multipart_upload{
		my $cb=shift;
	sub {
		my $line=$_[0];#shift;
		my $rex=$_[1];#shift;
		#shift;		#remove place holder for mime
		my $session=$rex->[uSAC::HTTP::Rex::session_];
		#check if content type is correct first
		#say "CONTENT TYPE ON UPLOAD: ", $rex->[headers_]{'CONTENT_TYPE'};
		unless (index($rex->[headers_]{'CONTENT_TYPE'},'multipart/form-data')>=0){
			$session->[uSAC::HTTP::Session::closeme_]=1;
			reply_simple $line,$rex, HTTP_UNSUPPORTED_MEDIA_TYPE,[] ,"multipart/formdata required";
			return;
		}
		uSAC::HTTP::Session::push_reader
		$session,
		make_form_data_reader @_, $session, $cb ;
		$session->[uSAC::HTTP::Session::read_]->(\$session->[uSAC::HTTP::Session::rbuf_],$rex);
		#$session->[uSAC::HTTP::Session::read_]->(\$session->[uSAC::HTTP::Session::rbuf_],$rex) if $session->[uSAC::HTTP::Session::rbuf_];
		return;
	}
}

#reads a post/put request
#handles HTTP/1.1 continue
#checks mime types are as specified (any type is default)
#runs callback with parts of data
#
sub stream_upload {
	my $mime=shift//".*";#application/x-www-form-urlencoded';
	my $upload_limit=$UPLOAD_LIMIT;
	my $cb=shift;	#cb for parts

	sub {
		#my $line=shift;
		my $rex=$_[1];#shift;	#rex object

		my $session=$rex->[session_];
		say "CONTENT TYPE ON UPLOAD:", $rex->[headers_]{'CONTENT_TYPE'};
		say $mime;
		my @err_res;
		for($rex->[headers_]){
			if($_->{'CONTENT_TYPE'}!~/$mime/){
				@err_res=(HTTP_UNSUPPORTED_MEDIA_TYPE, [], "Must match $mime");
			}

			elsif($_->{'CONTENT_LENGTH'} > $upload_limit){
				@err_res=(HTTP_PAYLOAD_TOO_LARGE, [], "limit: $UPLOAD_LIMIT");
			}

			else{

				uSAC::HTTP::Session::push_reader
				$session,
				make_form_urlencoded_reader @_, $session, $cb ;

				#check for expects header and send 100 before trying to read
				if(defined($_->{EXPECTS})){
					#issue a continue response	
					say "writing continue";
					my $reply= "HTTP/1.1 ".HTTP_CONTINUE.LF.LF;
					$rex->[uSAC::HTTP::Rex::write_]->($reply);
				}

				$session->[uSAC::HTTP::Session::read_]->(\$session->[uSAC::HTTP::Session::rbuf_],$rex) if $session->[uSAC::HTTP::Session::rbuf_];
				return;
			}
		}

		$session->[uSAC::HTTP::Session::closeme_]=1;
		reply_simple @_, @err_res;#$line,$rex,@err_res; 
	}
}

sub stream_urlencoded_upload {
	stream_upload "application/x-www-form-urlencoded", shift;
}

#uses handle_upload or stream_multipart_upload setup for
#html forms
sub stream_form_upload {
	my ($cb)=@_;
	my $multi= stream_multipart_upload @_;
	my $url=stream_urlencoded_upload @_;
	sub{
		for ($_[1][headers_]{CONTENT_TYPE}){
			&$multi and return if /multipart\/form-data/;
			&$url and return if 'application/x-www-form-urlencoded';
			reply_simple $_[0],$_[1], HTTP_UNSUPPORTED_MEDIA_TYPE,[] ,"multipart/form-data or application/x-www-form-urlencoded required";
		}
	}
}

#process urlencoded form
#Return a set of kv pairs
#Last item is $cb
sub save_form {
	my $cb=pop;
	#The actual sub called
	#Expected inputs
	#	line, rex, data, part header, completeflag
	stream_urlencoded_upload sub {
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
		}
	}

}

#Writes any file attachments to temp files 
#NOTE only form-data/multipart
sub save_form_to_file {
	my $cb=pop;
	my %options=@_;
        my $tmp_dir=$options{dir}//"uploads";	#temp dir to save file to
        my $prefix=$options{prefix}//"uSAC";
	#The actual sub called
	stream_multipart_upload sub {
		my $usac=$_[0];
		my $rex=$_[1];
		state $part_header=0;
		state $kv;
		state $fields={};
		state ($handle,$name);

		if($part_header != $_[3]){
			#new part
			local $,=", ";
			$part_header=$_[3];
			close $handle if $handle;
			$name=$handle=undef;
			$kv=&parse_form_params;
			say "Parsed form";

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
		}
	}
}

#Handles either multipart or urlencoded body forms
#Callback is last argument and is called  on complete upload of all data
#Expected inputs to sub ref:
#	line, rex, data, part header, completeflag
sub save_web_form {
	my ($cb)=@_;
	my $multi= save_form_to_file @_;
	my $url=save_form @_;
	sub{
		for ($_[1][headers_]{CONTENT_TYPE}){
			&$multi and return if /multipart\/form-data/;
			&$url and return  if 'application/x-www-form-urlencoded';
			reply_simple $_[0],$_[1], HTTP_UNSUPPORTED_MEDIA_TYPE,[] ,"multipart/form-data or application/x-www-form-urlencoded required";
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

	stream_upload $mime, sub {
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
				$kv->{$key}=$value;
			}
			return $kv;
		}
		elsif('application/x-www-form-urlencoded'){
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


#Reply the body and code specified. Adds Server and Content-Length headers
#Line, Rex, code, header_ref, content

sub reply_simple{
	use integer;
	#my ($line, $self)=@_;
	#create a writer for the session
	my $session=$_[1]->[session_];
	\my $reply=\$session->[uSAC::HTTP::Session::wbuf_];
	my @headers=(
		[HTTP_DATE,		$uSAC::HTTP::Session::Date],
		[HTTP_CONTENT_LENGTH,	length ($_[4])+0],
		($session->[uSAC::HTTP::Session::closeme_]
			?[HTTP_CONNECTION,	"close"]
			:([	HTTP_CONNECTION,	"Keep-Alive"],
				[HTTP_KEEP_ALIVE,	"timeout=10, max=1000"]
			)
		)
	);
	#somehow call outerware before rendering?
	
	#my $outer=$_[0][4][1];
	#&$outer if $outer;

	

	$reply="HTTP/1.1 $_[2]".LF;
        ############################################################################
        # for my $h ($_[1]->[static_headers_]->@*, $headers->@*, ($_[3]//[])->@*){ #
        #         $reply.=$h->[0].": ".$h->[1].LF;                                 #
        # }                                                                        #
        ############################################################################
	$reply.= join "", map $_->[0].": ".$_->[1].LF, $_[1]->[static_headers_]->@*; 
	$reply.= join "", map $_->[0].": ".$_->[1].LF, @headers;
	$reply.= join "", map $_->[0].": ".$_->[1].LF, $_[3]->@* if $_[3];

	$reply.=LF.$_[4];
	$_[1][write_]($reply,$session->[uSAC::HTTP::Session::dropper_]);	#fire and forget
}


#rex, http_code, header, datacb 
sub reply_chunked{
	use integer;
	my ($matcher, $self, $code, $headers, $cb)=@_;
	#create a writer for the session
	my $session=$self->[session_];
	\my $reply=\$session->[uSAC::HTTP::Session::wbuf_];

	#my $content_length=length($_[4])+0;
	$reply= "HTTP/1.1 $code".LF;
	my @headers=(
		[HTTP_DATE,		$uSAC::HTTP::Session::Date],
		($session->[uSAC::HTTP::Session::closeme_]
			?[HTTP_CONNECTION,	"close"]
			:(	[HTTP_CONNECTION,	"Keep-Alive"],
				[HTTP_KEEP_ALIVE,	"timeout=10, max=1000"]
			)
		),
		[HTTP_TRANSFER_ENCODING, "chunked"]

	);


        ############################################################################
        # #render_v1_1_headers($reply, $headers, $self->[static_headers_], $_[3]); #
        # for my $h ($self->[static_headers_]->@*, $headers->@*, ($_[3]//[])->@*){ #
        #         $reply.=$h->[0].": ".$h->[1].LF;                                 #
        # }                                                                        #
        ############################################################################
	#
	$reply.= join "", map $_->[0].": ".$_->[1].LF, $_[1]->[static_headers_]->@*; 
	$reply.= join "", map $_->[0].": ".$_->[1].LF, @headers;
	$reply.= join "", map $_->[0].": ".$_->[1].LF, $_[3]->@* if $_[3];

	#Execute the filters based on headers
	#&{$_[0][4][1]};
	#
	#
	$reply.=LF;
	$self->[write_]($reply, $cb, uSAC::HTTP::Middleware::make_chunked_writer($session));
}

sub reply {
	my ($matcher, $self)=@_;#, $code, $headers, $cb)=@_;
	my $session=$self->[session_];
	#wrapper for simple and chunked
	# if the body element is a code ref, or array ref, then chunked is used
	for (ref $_[4]){
		reply_chunked @_ and return if $_ eq "CODE";
		if($_ eq "ARRAY"){
			#send each element of array as a chunk
			my $i=0;
			my $chunks=pop;
			#push @$chunks, "";

			reply_chunked @_, sub {
				$_[0]->($chunks->[$i++]//"", $i <= $chunks->@* ? __SUB__:$session->[uSAC::HTTP::Session::dropper_]);
			};
		}
		else{
			reply_simple @_;
		}
	}
}

########################################################################
# #reply with static content from specified path                       #
# sub reply_file {                                                     #
#         require uSAC::HTTP::Static;                                  #
#         my ($matcher, $self, $code, $headers, $path)=@_;             #
#         my $session=$self->[session_];                               #
#         local $_=$session->[uSAC::HTTP::Session::server_];           #
#         say Dumper $_;                                               #
#         my $root=dirname((caller)[1]);                               #
#         say "Root $root";                                            #
#         $root=rel2abs($root);                                        #
#                                                                      #
#         state $static=uSAC::HTTP::Static->new(root=>$root,%options); #
#         state $static=uSAC::HTTP::Static::usac_file_under($root);    #
#         \my $reply=\$session->[uSAC::HTTP::Session::wbuf_];          #
#         if($path =~ m|^[^/]|){                                       #
#                                                                      #
#                 #implicit path                                       #
#                 #make path relative to callers file                  #
#                 $path=dirname((caller)[1])."/".$path;                #
#         }                                                            #
#         say "Path $path";                                            #
#         $static->($matcher, $rex,   $path);                          #
#                                                                      #
# }                                                                    #
########################################################################



	 
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

#returns parsed cookies from headers
#Only parses if the internal field is undefined
#otherwise uses pre parsed values
sub cookies {
	$_[0][cookies_]//($_[0][cookies_]=usac_parse_cookie $_[0][headers_]{COOKIE});
}

sub state {
	$_[0][state_]=$_[1] if $_[1];
	$_[0][state_];
}


*rex_headers=*headers;
*rex_reply_simple=*reply_simple;
*rex_reply_chunked=*reply_chunked;
*rex_reply=*reply;

#Streamed with octets as they become available
*rex_stream_upload=*stream_upload;			#normal file	
*rex_stream_multipart_upload=*stream_multipart_upload;	#multipart 
*rex_stream_urlencoded_upload=*stream_urlencoded_upload;#like normal but forced mime type
*rex_stream_form_upload=*stream_form_upload;		#Automatially handles multipart and urlencoded form upload streams

*rex_parse_form_params=*parse_form_params;
*rex_query_params=*query_params;

#Called when upload is complete
*rex_save_to_file=*save_to_file;			#save general file
*rex_save_form_to_file=*save_form_to_file;		#save multipart files to disk
*rex_save_form=*save_form;				#process form when complete ready
*rex_save_web_form=*save_web_form;
1;
