#package AnyEvent::HTTP::Server::Form;

package uSAC::HTTP::Rex;
use version; our $VERSION = version->declare('v0.1');
use common::sense;
use feature "refaliasing";
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

our @EXPORT_OK=qw<rex_headers rex_reply_simple>;
our @EXPORT=@EXPORT_OK;




use Time::HiRes qw/gettimeofday/;
use Scalar::Util qw(weaken);
		


#Class attribute keys
#method_ uri_
#ctx_ reqcount_ 
use enum (
	"version_=0" ,qw<session_
	headers_ write_ query_ server_ time_ cookies_ handle_ attrs_>
);

#Add a mechanism for sub classing
use constant KEY_OFFSET=>0;
use constant KEY_COUNT=>attrs_-version_+1;


                #################################################################################################################################################
                # sub connection { $_[0][headers_]{connection} =~ /^([^;]+)/ && lc( $1 ) }                                                                      #
                #                                                                                                                                               #
                # sub method  { $_[0][method_] }                                                                                                                #
                # sub full_uri { 'http://' . $_[0][headers_]{host} . $_[0][uri_] }                                                                              #
                # sub uri     { $_[0][uri_] }                                                                                                                   #
                # sub headers { $_[0][headers_] }                                                                                                               #
                # sub attrs   { $_[0][attrs_] //= {} }                                                                                                          #
                # sub server  { $_[0][server_] }                                                                                                                #
                #                                                                                                                                               #
                #                                                                                                                                               #
                #                                                                                                                                               #
                #                                                                                                                                               #
                # sub uri_parse {                                                                                                                               #
                #         $_[0][parsed_uri_] = [                                                                                                                #
                #                 $_[0][uri_] =~ m{ ^                                                                                                           #
                #                         (?:                                                                                                                   #
                #                                 (?:(?:([a-z]+):|)//|)                                                                                         #
                #                                 ([^/]+)                                                                                                       #
                #                         |)                                                                                                                    #
                #                         (/[^?]*)                                                                                                              #
                #                         (?:                                                                                                                   #
                #                                 \? (.+|)                                                                                                      #
                #                                 |                                                                                                             #
                #                         )                                                                                                                     #
                #                 $ }xso                                                                                                                        #
                #         ];                                                                                                                                    #
                #         # $_[0][5][2] = url_unescape( $_[0][5][2] );                                                                                          #
                #         $_[0][query_] = +{ map { my ($k,$v) = split /=/,$_,2; +( url_unescape($k) => url_unescape($v) ) } split /&/, $_[0][parsed_uri_][3] }; #
                # }                                                                                                                                             #
                #                                                                                                                                               #
                #                                                                                                                                               #
                # sub path    {                                                                                                                                 #
                #         $_[0][parsed_uri_] or $_[0]->uri_parse;                                                                                               #
                #         $_[0][parsed_uri_][2];                                                                                                                #
                # }                                                                                                                                             #
                #                                                                                                                                               #
                # sub query    {                                                                                                                                #
                #         $_[0][parsed_uri_] or $_[0]->uri_parse;                                                                                               #
                #         $_[0][parsed_uri_][3];                                                                                                                #
                # }                                                                                                                                             #
                #                                                                                                                                               #
                # sub params {                                                                                                                                  #
                #         $_[0][query_] or $_[0]->uri_parse;                                                                                                    #
                #         $_[0][query_];                                                                                                                        #
                # }                                                                                                                                             #
                #                                                                                                                                               #
                # sub param {                                                                                                                                   #
                #         $_[0][query_] or $_[0]->uri_parse;                                                                                                    #
                #         if ($_[1]) {                                                                                                                          #
                #                 return $_[0][query_]{$_[1]};                                                                                                  #
                #         } else {                                                                                                                              #
                #                 return keys %{ $_[0][query_] };                                                                                               #
                #         }                                                                                                                                     #
                # }                                                                                                                                             #
                #################################################################################################################################################
		
sub reply_simple;
		
	

		sub reply_GZIP {

		}

		#like simple reply but does a DEFLATE on the data.
		#Sets the headers accordingly
		sub reply_DEFLATE {
			#call replySimple with extra headers
		}

        ##############################################################################################################
        # sub reply_headers {                                                                                        #
        #         my ($line,$self,$code,$headers)=@_;                                                                #
        #         my $session=$self->[session_];                                                                     #
        #         my $chunker=uSAC::HTTP::Session::select_writer $session, "http1_1_socket_writer";                  #
        #                                                                                                            #
        #                 my $reply="HTTP/1.1 $code".LF;                                                             #
        #                 #my $content_length=length($_[4])+0;                                                       #
        #                 $reply.=                                                                                   #
        #                         STATIC_HEADERS                                                                     #
        #                         .HTTP_DATE.": ".$uSAC::HTTP::Server::Date.LF                                       #
        #                         #.HTTP_CONTENT_LENGTH.": ".$content_length.LF   #this always render content length #
        #                         ;#if defined $_[1];     #Set server                                                #
        #                                                                                                            #
        #                         #TODO: benchmark length(undef)+0;                                                  #
        #                                                                                                            #
        #                 #close connection after if marked                                                          #
        #                 if($session->[uSAC::HTTP::Session::closeme_]){                                             #
        #                         $reply.=HTTP_CONNECTION.": close".LF;                                              #
        #                                                                                                            #
        #                 }                                                                                          #
        #                                                                                                            #
        #                 #or send explicit keep alive?                                                              #
        #                 elsif($self->[version_] ne "HTTP/1.1") {                                                   #
        #                         $reply.=                                                                           #
        #                                 HTTP_CONNECTION.": Keep-Alive".LF                                          #
        #                                 .HTTP_KEEP_ALIVE.": timeout=5, max=1000".LF                                #
        #                         ;                                                                                  #
        #                 }                                                                                          #
        #                                                                                                            #
        #                                                                                                            #
        #                 #User requested headers.                                                                   #
        #                 my $i=0;                                                                                   #
        #                 \my @headers=$_[3]//[];                                                                    #
        #                 for(0..@headers/2-1){                                                                      #
        #                         $reply.=$headers[$i++].": ".$headers[$i++].LF                                      #
        #                 }                                                                                          #
        #                                                                                                            #
        # }                                                                                                          #
        ##############################################################################################################


		#multipart for type.
		#Sub parts can be of different types and possible content encodings?
		sub handle_form_upload {
			my $line=shift;
			my $rex=shift;
			my $cb=shift;
			my $session=$rex->[uSAC::HTTP::Rex::session_];
			#check if content type is correct first
			say "CONTENT TYPE ON UPLOAD: ", $rex->[headers_]{'content-type'};
			unless (index($rex->[headers_]{'content-type'},'multipart/form-data')>=0){
				$session->[uSAC::HTTP::Session::closeme_]=1;
				reply_simple $line,$rex, HTTP_UNSUPPORTED_MEDIA_TYPE,undef,"multipart/formdata required";
				return;
			}
			uSAC::HTTP::Session::push_reader
				$session,
				"http1_1_form_data",

				$cb
			;
			$session->[uSAC::HTTP::Session::read_]->(\$session->[uSAC::HTTP::Session::rbuf_],$rex);

		}
		#percent/urlencoded data
		#possible content-encoding as well?
		sub handle_urlencode_upload {
			my $line=shift;
			my $rex=shift;	#rex object
			my $mime=shift//'application/x-www-form-urlencoded';
			my $cb=shift;	#cb for parts
			my $session=$rex->[session_];
			say "CONTENT TYPE ON UPLOAD: ", $rex->[headers_]{'content-type'};
			my @err_res;
			given($rex->[headers_]){
				when(index($_->{'content-type'},$mime)<0){
					@err_res=(HTTP_UNSUPPORTED_MEDIA_TYPE, undef, "applcation/x-www-form-urlencoded required");
				}
				when($_->{'content-length'} > $UPLOAD_LIMIT){
					@err_res=(HTTP_PAYLOAD_TOO_LARGE, undef, "limit: $UPLOAD_LIMIT");
				}
				default{

					uSAC::HTTP::Session::push_reader
						$session,
						"http1_1_urlencoded",
						$cb
					;

					#check for expects header and send 100 before trying to read
					#given($rex->[uSAC::HTTP::Rex::headers_]){
					if(defined($_->{expects})){
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

			my $content_length=length($_[4])+0;
			my $reply=
				"HTTP/1.1 $_[2]".LF
				#.STATIC_HEADERS
				.HTTP_DATE.": ".		$uSAC::HTTP::Server::Date.LF
				.HTTP_CONTENT_LENGTH.": ".	$content_length.LF
				.($session->[uSAC::HTTP::Session::closeme_]
					?HTTP_CONNECTION.": close".LF

					:"")
				.(($self->[version_] ne "HTTP/1.1")
					?HTTP_CONNECTION.": ".	"Keep-Alive".LF
					.HTTP_KEEP_ALIVE.": ".	"timeout=5, max=1000".LF

					:"")
				;
			render_v1_1_headers  $reply, $_[3] if $_[3];

			#Append body
			#say "Length: ", length($_[4])+0;
			if($content_length< 1048576){
				$reply.=LF.$_[4];
				$self->[write_]($reply, \&uSAC::HTTP::Session::drop); 
			}

			else{

				#only send data chunks at a time
				$reply.=LF;#.$_[4];
				\my $body=\$_[4];
				my $hcb=sub {
					$self->[write_]($body, \&uSAC::HTTP::Session::drop);

				};
				$self->[write_]($reply,$hcb);

			}
			#Write the headers
		}

sub render_v1_1_headers {
	\my $buffer=\$_[0];
	my $i=0;
	\my @headers=$_[1]//[];
	#say "RENDERING HEADERS ", @headers;
	for(0..@headers/2-1){
		$buffer.=join(": ",@headers[($i++,$i++)]).LF;#.": ".$headers[$i++].LF 
	}
}
	 

sub headers {
	return $_[0]->[headers_];
}

*rex_headers=*headers;
*rex_reply_simple=*reply_simple;
#returns parsed cookies from headers
#Only parses if the internal field is undefined
#otherwise uses pre parsed values
sub cookies {
	$_[0][cookies_]=parse_cookie $_[0][headers_]{cookie} unless $_[0][cookies_]//0;
	$_[0][cookies_];
}

1;

__END__
