package uSAC::HTTP::v1_1_Reader;
use common::sense;
use feature qw<refaliasing say switch>;
no warnings "experimental";

use Exporter 'import';
use Encode qw<decode encode decode_utf8>;

use Data::Dumper;
#$Data::Dumper::Deparse=1;
our @EXPORT_OK=qw<
		make_reader
		make_form_data_reader
		make_plain_text_reader
		make_form_urlencoded_reader
		make_default_writer
		make_socket_writer
		uri_decode
		parse_form
		>;

our @EXPORT=@EXPORT_OK;

use constant MAX_READ_SIZE => 128 * 1024;

use Errno qw(EAGAIN EINTR);
use AnyEvent::Util qw(WSAEWOULDBLOCK guard AF_INET6 fh_nonblocking);
use Time::HiRes qw/gettimeofday/;
use Scalar::Util 'refaddr', 'weaken';

#use uSAC::HTTP::Server;
use uSAC::HTTP::Session;
use uSAC::HTTP::Rex;
use constant MAX_READ_SIZE => 128 * 1024;

our $MIME;
sub DEBUG () { 0 }
our $LF = "\015\012";

#my $HEADER_QR=> qr/\G ([^:\000-\037\040]++):[\011\040]*+ ([^\012\015]*+) [\011\040]*+ \015\012/sxogca;
use constant LF=>"\015\012";
use enum (qw<STATE_REQ_LINE STATE_RES_LINE STATE_HEADERS STATE_ERROR>);

sub uri_decode {
	my $octets= shift;
	$octets=~ s/\+/ /sg;
	$octets=~ s/%([[:xdigit:]]{2})/chr(hex($1))/ge;
	return decode_utf8($octets);
	#return decode("utf8", $octets);
}

sub parse_form {
	map { (split "=", $_)} split "&", $_[0] =~ tr/ //dr;
}

#read request line
#read headers
#execute callback to perform uri/method/other matching based on headers
#	-could also be an protocol upgrade => push a dedicated reader to the read stack
#	-method could contain data => push a dedicated reader to the read stack
#
#

sub make_reader{
	#say "MAKING BASE HTTP1.1 reader";
	#take a session and alias the variables to lexicals
	my $r=shift;

	my $self=$r->[uSAC::HTTP::Session::server_];
	\my $buf=\$r->[uSAC::HTTP::Session::rbuf_];
	\my $fh=\$r->[uSAC::HTTP::Session::fh_];
	\my $write=\$r->[uSAC::HTTP::Session::write_];
	#weaken $write;
	weaken $r;

	my $cb=$self->current_cb;#$self->[uSAC::HTTP::Server::cb_];
	my $enable_hosts=$self->enable_hosts;
	my ($state,$seq) = (0,0);
	my ($method,$uri,$version,$lastkey,$contstate,$bpos,$len,$pos, $req);
	my $line;

	my $ixx = 0;
	my %h;		#Define the header storage here, once per connection
	# = ( INTERNAL_REQUEST_ID => $id, defined $rhost ? ( Remote => $rhost, RemotePort => $rport ) : () );
	sub {
		use integer;
		#$self and $r or return;
		$len=length $buf;
		while ( $self and $len ) {
			#Dual mode variables:
			#	server:
			#	$method => method
			#	$url => uri
			#	$version => http version
			#
			#	client:
			#	$method=> http version
			#	$url=> status code
			#	$version => comment
			#
			if ($state == 0) {
				my $pos3=index $buf, LF, $ixx;
                                $line=substr($buf,$ixx,$pos3);
				($method,$uri,$version)=split " ",$line;
				#$version=substr($line,-1,1)eq "1"?"HTTP/1.1":"HTTP/1.0";
                                $line=uri_decode substr($buf,$ixx,$pos3-length($version)-1);
				if($pos3>=0){
					#end of line found
						$state   = 1;
						$lastkey = undef;
						#Reset header information for each request	
						%h=();
						#%h = ( INTERNAL_REQUEST_ID => $id, defined $rhost ? ( Remote => $rhost, RemotePort => $rport ) : () );
						++$seq;

						#$self->[uSAC::HTTP::Server::active_requests_]++;
						$pos=$pos3+2;
						redo;
				}
				else {
					#need more. wait for event
					#Don't update $pos
					# could also be an error... need time out
				}
			}

			# warn "rw.io.$id.rd $len ($state) -> $pos";
			elsif ($state == 1) {
				# headers
				pos($buf) = $pos;
				while () {	#TODO: check time out and bytes size to stop tight loop
					#TODO:
					#Need to exit loop on error... some type of guard?
					# Explicit support for multiple cookies. Possibly use seperate cookies list?
					# Treat all headers as 'list' format for this round of parsing. 
					# Understand what the continuation is supposed to achieve. Its depricated
					#  
					#warn "parse line >'".substr( $buf,pos($buf),index( $buf, "\012", pos($buf) )-pos($buf) )."'";

					if( $buf =~ /\G ([^:\000-\037\040]++):[\011\040]*+ ([^\012\015]*+) [\011\040]*+ \015\012/sxogca ){
						\my $e=\$h{uc $1=~tr/-/_/r};
						$e = defined $e ? $e.','.$2: $2;
					}
					elsif ($buf =~ /\G\015?\012/sxogca) {
						#warn "Last line";
						last;
					}
					elsif($buf =~ /\G [^\012]* \Z/sxogca) {
						if (length($buf) - $ixx > MAX_READ_SIZE) {
							#$self->[uSAC::HTTP::Server::max_header_size_]) {
							$self->badconn($fh,\substr($buf, pos($buf), $ixx), "Header overflow at offset ".$pos."+".(length($buf)-$pos));
							return $r->drop( "Too big headers from rhost for request <".substr($buf, $ixx, 32)."...>");
						}
						#warn "Need more";
						return pos($buf) = $bpos; # need more data
					}
					else {
						my ($line) = $buf =~ /\G([^\015\012]++)(?:\015?\012|\Z)/sxogc;
						#$self->[uSAC::HTTP::Server::active_requests_]--;
						$self->badconn($fh,\$line, "Bad header for <$method $uri>+{@{[ %h ]}}");
						my $content = 'Bad request headers';
						my $str = "HTTP/1.1 400 Bad Request${LF}Connection:close${LF}Content-Type:text/plain${LF}Content-Length:".length($content)."${LF}${LF}".$content;
						$write->($str);
						$write->(undef);
						return;
					}
				}
				#Done with headers. 
				#
				#TODO: downsample gettimeofday to a second
				$req = bless [ $version, $r, \%h, $write, undef, $self, 1 ,undef,undef,undef,$method, $uri], 'uSAC::HTTP::Rex' ;
				#$req = bless [ $version, $r, $method, $uri, \%h, $write, undef,undef,undef, \$self->[uSAC::HTTP::Server::active_requests_], $self, scalar gettimeofday() ,undef,undef,undef,undef], 'uSAC::HTTP::Rex' ;


				$pos = pos($buf);

				#$self->[uSAC::HTTP::Server::total_requests_]++;
				$r->[uSAC::HTTP::Session::rex_]=$req;
				$r->[uSAC::HTTP::Session::closeme_]= !( $version eq "HTTP/1.1" or $h{CONNECTION} =~/^Keep-Alive/ );

				#shift buffer
				$buf=substr $buf,$pos;
				$pos=0;
				$ixx=0;
				$state=0;
				#$self->[uSAC::HTTP::Server::cb_]($line,$req);
				$line=($h{HOST}//"")." $line" if $enable_hosts;
				$cb->($line,$req);
				weaken ($req->[1]);
				#weaken( $req->[8] );
				weaken( $req->[5] );
				return;


			} # state 1
			else {
			}
		} # while read
	}; # io
}


#HTML FORM readers
#
#This reads http1/1.1 post type 
#Body is multiple parts  seperated by a boundary. ie no length
#
#Headers required:
#Content-Type: multipart/form-data;boundary="boundary"
#NO Content-Length

# multipart/form-data; boundary=------border
# Basically scan through the entire contents of the body and locate the border stirng 
sub make_form_data_reader {
	use integer;
	my $session=shift;
	\my $buf=\$session->[uSAC::HTTP::Session::rbuf_];
	\my $cb=\$session->[uSAC::HTTP::Session::reader_cb_];
	\my $rex=\$session->[uSAC::HTTP::Session::rex_];


	my $state=0;
	my $first=1;
	##my %h;
	my $form_headers={};

	sub {
		say "IN FORM PARSER";
		#\my $buf=shift;#buffer from io loop
		#my $rex=shift;
		#my $cb=$session->[uSAC::HTTP::Session::reader_cb_];
		my $processed=0;

		\my %h=$rex->[uSAC::HTTP::Rex::headers_];
		my $type = $h{'content-type'};
		say "content type: $type";
		#TODO: check for content-disposition and filename if only a single part.
		my $boundary="--".(split("=", $type))[1];
		say  "boundary:",$boundary;
		my $b_len=length $boundary;
		#say "buffer len:", length $buf;
		#say "buffer:", $buf;
		while($processed < length $buf){
			given($state){
				when(0){
					say "STATE $state. Looking for boundary";
					#%h=();
					#Attempt to match boundary
					my $index=index($buf,$boundary,$processed);
					if($index>=0){

						say "FOUND boundary and index: $index first: $first";
						#send partial data to callback
						my $len=($index-2)-$processed;	#-2 for LF

						say "Headers: ",Dumper $form_headers;
						$cb->(substr($buf,$processed,$len),$form_headers) unless $first;
						$first=0;

						#move past data and boundary
						$processed+=$index+$b_len;

						#end search
						#say "buffer:",substr $buf, $processed;


						#test if this is the last boundary
						if(substr($buf,$processed,4) eq "--".LF){
							#END OF MULTIPART FORM
							#Remove from io stack
							#callback with undef?
							say "END OF MULTIPART";
							$processed+=4;

							#update buffer for readstack
							$buf=substr $buf,$processed;
							say $buf;
							$cb->(undef,$form_headers);
							uSAC::HTTP::Session::pop_reader($session);
							#$session->pop_reader;
							return;
						}
						elsif(substr($buf,$processed,2) eq LF){
							#it wasn't last part, so move to next state
							#reset headers now
							$form_headers={};
							say "moving to next state";
							$processed+=2;
							$state=1;
							redo;
						}
					}

					else {
						say "NOT FOUND boundary and index: $index";
						# Full boundary not found, send partial, upto boundary length
						my $len=length($buf)-$b_len;		#don't send boundary
						say Dumper $form_headers;
						$cb->(substr($buf, $processed, $len),$form_headers);
						$processed+=$len;
						#wait for next read now
						return;
					}

					#attempt to match extra hyphons
					#next line after boundary is content disposition

				}

				when(1){
					#read any headers
					say "State  $state. READING HEADERS";
					pos($buf)=$processed;

					while (){
						if( $buf =~ /\G ([^:\000-\037\040]++):[\011\040]*+ ([^\012\015]*+) [\011\040]*+ \015\012/sxogca ){
							\my $e=\$form_headers->{lc $1};
							$e = defined $e ? $e.','.$2: $2;
							say "Got header: $e";

							#need to split to isolate name and filename
							redo;
						}
						elsif ($buf =~ /\G\015\012/sxogca) {
							say "HEADERS DONE";
							$processed=pos($buf);

							#readjust the buffer no
							$buf=substr $buf,$processed;
							$processed=0;

							#say "Buffer:",$buf;
							#headers done. setup

							#go back to state 0 and look for boundary
							$state=0;
							last;
							#process disposition
							given($form_headers->{'content-disposition'}){
								when(undef){
									#this is an error
								}
								default {
									#parse fields, and filenames
									#Content-Disposition: form-data; name="image"; filename="mybook.png"
									my @params=split /; +/; 
									$params[0] eq "form-data";
									my @form=split "=", $params[1];
									#quoted?		
									my @filename=split "=". $params[2];

								}
							}

							#process content-type
							given($form_headers->{'content-type'}){
								when(undef){
									#not set
								}
								default {
								}
							}

							#process content type
							$form_headers->{'content-type'};


							#if headers are ok then look for boundary
							#
							$state=0;
							last;
						}
						else {

						}
					}

					#update the offset
					$processed=pos $buf;

				}

				default {
					say "DEFAULT";

				}
			}
			say "End of while";
		}
		say "End of form reader";
	}


}

sub make_plain_text_reader {

}


#This reads http1/1.1 post type 
#Headers required:
#Content-Length:  length
#Content-Type: application/x-www-form-urlencoded
#
sub make_form_urlencoded_reader {
	say "MAKING URL ENCODED READER";
	use integer;
	#These values are shared for a session
	#
	my $session=shift;
	\my $buf=\$session->[uSAC::HTTP::Session::rbuf_];	#Alias buffer (not a reference)
	\my $cb=\$session->[uSAC::HTTP::Session::reader_cb_];	#Alias reference to current cb
	\my $rex=\$session->[uSAC::HTTP::Session::rex_];	#Alias refernce to current rexx
	my $form_headers={};					#Not really used but required for cb	
	my $processed=0;					#stateful position in buffer
	
	#Actual Reader. Uses the input buffer stored in the session. call back is also pushed
	sub {
		\my %h=$rex->[uSAC::HTTP::Rex::headers_];	#
		my $len = $h{'content-length'}//0; #number of bytes to read, or 0 if undefined

		my $new=length($buf)-$processed;	#length of read buffer

		$new=$new>$len?$len:$new;		#clamp to content length
		$cb->(substr($buf,0,$new,""),$form_headers);		#send to cb and shift buffer down
		$processed+=$new;			#track how much we have processed

		#when the remaining length is 0, pop this sub from the stack
		if($processed==$len){
			$cb->(undef,$form_headers);
			#return to the previous 
			$processed=0;
			#$session->pop_reader;	#This assumes that the normal 1.1 reader previous in the stack
			uSAC::HTTP::Session::pop_reader $session;
			#issue a read since reader has changed
			#$session->[uSAC::HTTP::Session::read_]->(\$session->[uSAC::HTTP::Session::rbuf_],$rex);
		}
		else {
			#keep on stack until done
		}

	}
}

############################################################################################################
# sub make_default_writer{                                                                                 #
#         #take a session and alias the variables to lexicals                                              #
#         my $ido=shift;                                                                                   #
#         weaken $ido;                                                                                     #
#         \my $wbuf=\$ido->[uSAC::HTTP::Session::wbuf_];                                                   #
#         \my $ww=\$ido->[uSAC::HTTP::Session::ww_];                                                       #
#         \my $fh=\$ido->[uSAC::HTTP::Session::fh_];                                                       #
#         my $w;                                                                                           #
#         my $cb;                                                                                          #
#         my $arg;                                                                                         #
#                                                                                                          #
#         sub {                                                                                            #
#                 \my $buf=\$_[0];        #give the input a name, but no copy                              #
#                 $cb=$_[1];              #save callback here                                              #
#                 $arg=$_[2]//__SUB__;    #argument is 'self' unless one is provided                       #
#                 #local $\=", ";                                                                          #
#                 say "Calling write: $buf";                                                               #
#                 #say caller;                                                                             #
#                 if(length($wbuf) == 0 ){                                                                 #
#                         $w = syswrite( $fh, $buf );                                                      #
#                         given ($w){                                                                      #
#                                 when(length $buf){                                                       #
#                                         #say "FULL WRITE NO APPEND";                                     #
#                                         $wbuf="";                                                        #
#                                         #$ww=undef;                                                      #
#                                         $cb->($arg) if $cb;                                              #
#                                         return;                                                          #
#                                                                                                          #
#                                 }                                                                        #
#                                 when(defined $w and length($buf)> $w){                                   #
#                                         say "PARITAL WRITE NO APPEND: wanted". length($buf). "got $w";   #
#                                         $wbuf.=substr($buf,$w);                                          #
#                                         return if defined $ww;                                           #
#                                                                                                          #
#                                 }                                                                        #
#                                 default {                                                                #
#                                         unless( $! == EAGAIN or $! == EINTR){                            #
#                 say "IN WRITER: @_";                                                                     #
#                                                 say "ERROR IN WRITE NO APPEND";                          #
#                                                 say $!;                                                  #
#                                                 #actual error                                            #
#                                                 $ww=undef;                                               #
#                                                 #$wbuf="";                                               #
#                                                 #$ido->drop( "$!");                                      #
#                                                 $cb->(undef);   #error                                   #
#                                                 uSAC::HTTP::Session::drop "$!";                          #
#                                                 return;                                                  #
#                                         }                                                                #
#                                 }                                                                        #
#                         }                                                                                #
#                                                                                                          #
#                 }                                                                                        #
#                 else {                                                                                   #
#                         $wbuf.= $buf;                                                                    #
#                         $w = syswrite( $fh, $wbuf );                                                     #
#                         given($w){                                                                       #
#                                 when(length $wbuf){                                                      #
#                                         say "Full write from appended";                                  #
#                                         $ww=undef;                                                       #
#                                         $wbuf="";                                                        #
#                                         $cb->($arg) if $cb;                                              #
#                                         return;                                                          #
#                                 }                                                                        #
#                                 when (length($wbuf)> $w){                                                #
#                                         say "partial write from appended";                               #
#                                         $wbuf.=substr($wbuf,$w);                                         #
#                                         #need to create watcher if it does                               #
#                                         return if defined $ww;                                           #
#                                                                                                          #
#                                 }                                                                        #
#                                 default{                                                                 #
#                                         #error                                                           #
#                                         unless( $! == EAGAIN or $! == EINTR){                            #
#                                                 #actual error                                            #
#                                                 $ww=undef;                                               #
#                                                 #$wbuf="";                                               #
#                                                 #$ido->drop( "$!");                                      #
#                                                 $cb->(undef) if $cb;                                     #
#                                                 uSAC::HTTP::Session::drop "$!";                          #
#                                                 return;                                                  #
#                                         }                                                                #
#                                         return if defined $ww;                                           #
#                                 }                                                                        #
#                         }                                                                                #
#                 }                                                                                        #
#                                                                                                          #
#                 say "making watcher";                                                                    #
#                 $ww = AE::io $fh, 1, sub {                                                               #
#                         say "IN WRITE WATCHER CB";                                                       #
#                         $ido or return;                                                                  #
#                         $w = syswrite( $fh, $wbuf );                                                     #
#                         given($w){                                                                       #
#                                 when(length $wbuf) {                                                     #
#                                         say "FULL async write";                                          #
#                                         $wbuf="";                                                        #
#                                         undef $ww;                                                       #
#                                         $cb->($arg) if $cb;                                              #
#                                         #if( $ido->[closeme_] ) { $ido->drop(); }                        #
#                                 }                                                                        #
#                                 when(defined $w){                                                        #
#                                         say "partial async write";                                       #
#                                         $wbuf= substr( $wbuf, $w );                                      #
#                                 }                                                                        #
#                                 default {                                                                #
#                                         #error                                                           #
#                                         return if $! == EAGAIN or $! == EINTR;#or $! == WSAEWOULDBLOCK){ #
#                                         #actual error                                                    #
#                                         say "WRITER ERROR: ", $!;                                        #
#                                         $ww=undef;                                                       #
#                                         $wbuf="";                                                        #
#                                         #$ido->drop( "$!");                                              #
#                                         $cb->(undef) if $cb;                                             #
#                                         uSAC::HTTP::Session::drop "$!";                                  #
#                                         return;                                                          #
#                                 }                                                                        #
#                         }                                                                                #
#                 };                                                                                       #
#                 #else { return $ido->drop("$!"); }                                                       #
#         };                                                                                               #
# }                                                                                                        #
#                                                                                                          #
############################################################################################################
#lowest level of the stream stack
#Inputs are buffer, callback, callback arg
#if callback is not provided, the 'dropper' for the session is used.
#in when the write is complete, the callback is called with the argument.
#if an error occored the callback is called with undef.
#
sub make_socket_writer{
	#take a session and alias the variables to lexicals
	my $ido=shift;
	weaken $ido;
	my $wbuf;# $$wbuf="";# buffer is for this sub only \$ido->[uSAC::HTTP::Session::wbuf_];
	\my $ww=\$ido->[uSAC::HTTP::Session::ww_];
	\my $fh=\$ido->[uSAC::HTTP::Session::fh_]; #reference to file handle.
	weaken $fh;
	my $w;
	my $offset=0;
	say  "++Making socket writer";

	#Arguments are buffer and callback.
	#do not call again until callback is called
	#if no callback is provided, the session dropper is called.
	#
	sub {
		use integer;
		say "IN WRITER: @_";

		($_[0]//0) or return;		#undefined input. was a stack reset

		\my $buf=\$_[0];		#give the input a name

		my $cb= $_[1]//$ido->[uSAC::HTTP::Session::dropper_];#sub {};			#give the callback a name
		
		#say "writer cb is: ", Dumper $cb;
		my $arg=$_[2]//__SUB__;
		$offset=0;# if $pre_buffer!=$_[0];	#do offset reset if need beo
		#$pre_buffer=$_[0];

		if(!$ww){	#no write watcher so try synchronous write
			$w = syswrite( $fh, $buf, length($buf)-$offset, $offset);
			$offset+=$w;
			if($offset==length $buf){
				say "FULL WRITE NO APPEND";
				#say "writer cb is: $cb";
				$cb->($arg);
				#$cb->($ido);
				return;
			}
			elsif(defined $w){# and length($buf)> $w){
				#say "PARITAL WRITE NO APPEND: wanted". length($buf). "got $w";
				#say "making watcher";
				#$wbuf=\$buf;
				$ww = AE::io $fh, 1, sub {
					$ido or return;
					$w = syswrite( $fh, $buf, length($buf)-$offset, $offset);

					$offset+=$w;
					if($offset==length $buf) {
						say "FULL async write";
						undef $ww;
						$cb->($arg);# if defined $cb;
					}
					elsif(defined $w){
						say "partial async write";
						#$$cb->((length ($buf) - $offset) ) if defined $$cb;
					}
					else{
						#error
						return if $! == EAGAIN or $! == EINTR;#or $! == WSAEWOULDBLOCK){
						$ww=undef;
						$cb->(undef);
						#uSAC::HTTP::Session::drop $ido, "$!";
						return;
					}
				};
				return

			}
			else {
				unless( $! == EAGAIN or $! == EINTR){

					say "ERROR IN WRITE NO APPEND";
					say $!;
					#actual error		
					$ww=undef;
					$cb->(undef);
					#uSAC::HTTP::Session::drop $ido, "$!";
					return;
				}
			}

		}
		return
	};
}
1;
