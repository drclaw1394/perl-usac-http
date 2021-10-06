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
		make_form_urlencoded_reader
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
	my $fh=$r->[uSAC::HTTP::Session::fh_];
	my $write=$r->[uSAC::HTTP::Session::write_];
	#weaken $write;
	weaken $r;

	my $cb=$self->current_cb;#$self->[uSAC::HTTP::Server::cb_];
	my $enable_hosts=$self->enable_hosts;
	my $static_headers=$self->static_headers;
	my ($state,$seq) = (0,0);
	my ($method,$uri,$version,$len,$pos, $req);
	my $line;

	my $ixx = 0;
	my %h;		#Define the header storage here, once per connection
	# = ( INTERNAL_REQUEST_ID => $id, defined $rhost ? ( Remote => $rhost, RemotePort => $rport ) : () );
	$r->[uSAC::HTTP::Session::read_]=sub {
		use integer;
		#$self and $r or return;
		$len=length $buf;
		while ( $len ) {
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
				$uri=uri_decode $uri;
				
				#$line=uri_decode substr($buf,$ixx,$pos3-length($version)-1);
				$line="$method $uri";
				if($pos3>=0){
					#end of line found
						$state   = 1;
						#$lastkey = undef;
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
						#say $e;
						redo;
					}
					elsif ($buf =~ /\G\015?\012/sxogca) {
						#warn "Last line";
						last;
					}
					elsif($buf =~ /\G [^\012]* \Z/sxogca) {
						if (length($buf) - $ixx > MAX_READ_SIZE) {
							#$self->[uSAC::HTTP::Server::max_header_size_]) {
							$self->badconn($fh,\substr($buf, pos($buf), $ixx), "Header overflow at offset ".$pos."+".(length($buf)-$pos));
							return $r->[uSAC::HTTP::Session::dropper_]->( "Too big headers from rhost for request <".substr($buf, $ixx, 32)."...>");
						}
						#warn "Need more";
						#say "need more";
						$pos=pos($buf);
						return;
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
				my $host=$h{HOST}//"";
				$req = bless [ $version, $r, \%h, $write, undef, $self, 1 ,undef,undef,undef,$host, $method, $uri, $uri, $static_headers], 'uSAC::HTTP::Rex' ;
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
				$line=$host." ".$line if $enable_hosts;
				$cb->($line,$req);
				#weaken ($req->[1]);
				#weaken( $req->[5] );
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

	my ($usac,$rex,$session,$cb)=@_;	
	#my $session=shift;
	\my $buf=\$session->[uSAC::HTTP::Session::rbuf_];
	#my $cb=shift;#\$session->[uSAC::HTTP::Session::reader_cb_];
	my $rex=$session->[uSAC::HTTP::Session::rex_];


	my $state=0;
	my $first=1;
	##my %h;
	my $form_headers={};

	sub {
		#\my $buf=shift;#buffer from io loop
		#my $rex=shift;
		#my $cb=$session->[uSAC::HTTP::Session::reader_cb_];
		my $processed=0;

		\my %h=$rex->headers;#[uSAC::HTTP::Rex::headers_];
		my $type = $h{'CONTENT_TYPE'};
		#TODO: check for content-disposition and filename if only a single part.
		my $boundary="--".(split("=", $type))[1];
		my $b_len=length $boundary;
		while($processed < length $buf){
			given($state){
				when(0){
					#say "STATE $state. Looking for boundary";
					#%h=();
					#Attempt to match boundary
					my $index=index($buf,$boundary,$processed);
					if($index>=0){
						

						#say "FOUND boundary and index: $index first: $first";
						#send partial data to callback
						my $len=($index-2)-$processed;	#-2 for LF



						#test if last
						my $offset=$index+$b_len;
						if(substr($buf,$offset,2)eq LF){
							#not last
							$cb->($usac, $rex, substr($buf,$processed,$len),$form_headers) unless $first;
							$first=0;
							#move past data and boundary
							$processed+=$offset+2;
							$buf=substr $buf, $processed;
							$processed=0;
							$state=1;
							$form_headers={};
							redo;

						}
						elsif(substr($buf,$offset,4) eq "--".LF){
							#say "END BOUNDARD FOUND";
							$first=1;	#reset first;
							$cb->($usac, $rex, substr($buf,$processed,$len),$form_headers,1);
							$processed+=$offset+4;
							$buf=substr $buf, $processed;
							$processed=0;
							uSAC::HTTP::Session::pop_reader($session);
							return;
						}
						else{
							#need more
							#say "need more";
							return
						}

					}

					else {
						#say "NOT FOUND boundary and index: $index";
						# Full boundary not found, send partial, upto boundary length
						my $len=length($buf)-$b_len;		#don't send boundary
						$cb->($usac, $rex, substr($buf, $processed, $len),$form_headers);#$form_headers);
						$processed+=$len;
						$buf=substr $buf, $processed;
						$processed=0;
						#wait for next read now
						return;
					}

					#attempt to match extra hyphons
					#next line after boundary is content disposition

				}

				when(1){
					#read any headers
					#say "State  $state. READING HEADERS";
					pos($buf)=$processed;

					while (){
						if( $buf =~ /\G ([^:\000-\037\040]++):[\011\040]*+ ([^\012\015]*+) [\011\040]*+ \015\012/sxogca ){
							\my $e=\$form_headers->{uc $1=~tr/-/_/r};
							$e = defined $e ? $e.','.$2: $2;
							#say "Got header: $e";

							#need to split to isolate name and filename
							redo;
						}
						elsif ($buf =~ /\G\015\012/sxogca) {
							#say "HEADERS DONE";
							$processed=pos($buf);

							#readjust the buffer no
							$buf=substr $buf,$processed;
							$processed=0;

							#say "Buffer:",$buf;
							#headers done. setup

							#go back to state 0 and look for boundary
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
					#say "DEFAULT";

				}
			}
			#say "End of while";
		}
		#say "End of form reader";
	}


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
	my ($usac,$rex,$session,$cb)=@_;	
	#my $session=shift;
	\my $buf=\$session->[uSAC::HTTP::Session::rbuf_];	#Alias buffer (not a reference)
	#my $cb=shift;#$_[1];#=$session->[uSAC::HTTP::Session::reader_cb_]=$_[1];	#Alias reference to current cb
	my $rex=$session->[uSAC::HTTP::Session::rex_];	#Alias refernce to current rexx
	my $processed=0;					#stateful position in buffer
	my $header={};
	#Actual Reader. Uses the input buffer stored in the session. call back is also pushed
	sub {
		
		\my %h=$rex->headers;#[uSAC::HTTP::Rex::headers_];	#
		my $len =
		$header->{CONTENT_LENGTH}=		#copy header to part header
		$h{'CONTENT_LENGTH'}//0; #number of bytes to read, or 0 if undefined

		$header->{CONTENT_TYPE}=$h{CONTENT_TYPE};

		my $new=length($buf)-$processed;	#length of read buffer

		$new=$new>$len?$len:$new;		#clamp to content length
		$processed+=$new;			#track how much we have processed

		#when the remaining length is 0, pop this sub from the stack
		if($processed==$len){
			$cb->($usac, $rex, substr($buf,0,$new,""),$header,1);		#send to cb and shift buffer down
			$header={};
			#$cb->(undef,undef);#$form_headers);
			#return to the previous 
			$processed=0;
			#$session->pop_reader;	#This assumes that the normal 1.1 reader previous in the stack
			uSAC::HTTP::Session::pop_reader $session;
			#issue a read since reader has changed
			#$session->[uSAC::HTTP::Session::read_]->(\$session->[uSAC::HTTP::Session::rbuf_],$rex);
		}
		else {
			#keep on stack until done
			$cb->($usac, $rex, substr($buf,0,$new,""),$header);		#send to cb and shift buffer down
		}

	}
}

#lowest level of the stream stack
#Inputs are buffer, callback, callback arg
#if callback is not provided, the 'dropper' for the session is used.
#in when the write is complete, the callback is called with the argument.
#if an error occored the callback is called with undef.
#
sub make_socket_writer_append{
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
				#say "FULL WRITE NO APPEND";
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
						#say "FULL async write";
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
sub make_socket_writer{
	#take a session and alias the variables to lexicals
	my $session=shift;
	weaken $session;
	my $wbuf;# $$wbuf="";# buffer is for this sub only \$ido->[uSAC::HTTP::Session::wbuf_];
	my $ww=$session->[uSAC::HTTP::Session::ww_];
	my $fh=$session->[uSAC::HTTP::Session::fh_]; #reference to file handle.
	weaken $fh;
	my $w;
	my $offset=0;
	#Arguments are buffer and callback.
	#do not call again until callback is called
	#if no callback is provided, the session dropper is called.
	#
	\my @queue=$session->[uSAC::HTTP::Session::write_queue_]; # data, offset, cb, arg

	$session->[uSAC::HTTP::Session::write_]=sub {
		use integer;

		$_[0]//return;		#undefined input. was a stack reset
		
		\my $buf=\$_[0];		#give the input a name

		my $dropper=$session->[uSAC::HTTP::Session::dropper_];	#default callback
		my $cb= $_[1]//$dropper;		#when no cb provided, use dropper
		my $arg=$_[2]//__SUB__;			#is this sub unless provided


		$offset=0;# if $pre_buffer!=$_[0];	#do offset reset if need beo
		#$pre_buffer=$_[0];
		#say "preview: ", substr($buf ,0 , 10),"length: ", length $_[0];
		if(!$ww){	#no write watcher so try synchronous write
			#say "No watcher";
			$w = syswrite( $fh, $buf, length($buf)-$offset, $offset);
			$session->[uSAC::HTTP::Session::time_]=$uSAC::HTTP::Session::Time;
			$offset+=$w;
			if($offset==length $buf){
				#say "FULL WRITE NO APPEND";
				#say "writer cb is: $cb";
				if($dropper == $cb){
					$cb->();
				}
				else {
					$cb->($arg);
                                        ###############################################
                                        # my $timer; $timer=AE::timer 0.0, 0.0, sub { #
                                        #         $cb->($arg);                        #
                                        #         $timer=undef;                       #
                                        # };                                          #
                                        ###############################################
				}
				return;
			}
			#else{
					
				#say "w is $w";
				if(!defined($w) and $! != EAGAIN and $! != EINTR){
					#this is actual error
					say "ERROR IN WRITE NO APPEND";
					say $!;
					#actual error		
					$ww=undef;
					@queue=();	#reset queue for session reuse
					$cb->(undef);
					$dropper->(1);
					#uSAC::HTTP::Session::drop $session, "$!";
					return;
				}

				#either a partial write or an EAGAIN situation

				#say "EAGAIN or partial write";
				#If the write was only partial, or had a async 'error'
				#push the buffer to setup events
				push @queue,[$buf,$offset,$cb,$arg];
				#say "PARTIAL WRITE Synchronous";
				my $entry;
				$ww = AE::io $fh, 1, sub {
					$session or return;
					$entry=$queue[0];
					\my $buf=\$entry->[0];
					\my $offset=\$entry->[1];
					\my $cb=\$entry->[2];
					\my $arg=\$entry->[3];
					$w = syswrite( $fh, $buf, length($buf)-$offset, $offset);
					$session->[uSAC::HTTP::Session::time_]=$uSAC::HTTP::Session::Time;

					$offset+=$w;
					if($offset==length $buf) {
						#say "FULL async write";
						shift @queue;
						undef $ww unless @queue;
						#$cb->($arg);# if defined $cb;
						if($dropper == $cb){
							$cb->();
						}
						else {
								$cb->($arg);
                                                        ###############################################
                                                        # my $timer; $timer=AE::timer 0.0, 0.0, sub { #
                                                        #         $cb->($arg);                        #
                                                        #         $timer=undef;                       #
                                                        # };                                          #
                                                        ###############################################
						}
						return;
					}

					if(!defined($w) and $! != EAGAIN and $! != EINTR){
						#this is actual error
						say "ERROR IN EVENT WRITE";
						say $!;
						#actual error		
						$ww=undef;
						@queue=();	#reset queue for session reuse
						$cb->(undef);
						$dropper->(1);
						#uSAC::HTTP::Session::drop $session, "$!";
						return;
					}
				};

				return
		}
		else {
			#watcher existing, add to queue
			#say "Watcher exists, pushing to queue+++";
			push @queue, [$buf,0,$cb,$arg];
		}
		return
	};
}
1;
