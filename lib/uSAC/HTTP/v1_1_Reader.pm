package uSAC::HTTP::v1_1_Reader;
use feature qw<fc current_sub refaliasing say>;
use strict;
use warnings;
no warnings "experimental";
use EV;
use Log::ger;
use Log::OK;
use Data::Dumper;

use Exporter 'import';
use Encode qw<find_encoding decode encode decode_utf8>;
use URL::Encode::XS;
use URL::Encode qw<url_decode_utf8>;
our @EXPORT_OK=qw<
		make_reader
		make_form_data_reader
		make_form_urlencoded_reader
		make_socket_writer
		parse_form
		MODE_SERVER
		MODE_CLIENT
		>;

our @EXPORT=@EXPORT_OK;


#Package global for decoding utf8. Faster than using decode_utf8 function.
our $UTF_8=find_encoding "utf-8";


use Time::HiRes qw/gettimeofday/;
use Scalar::Util 'refaddr', 'weaken';

use uSAC::HTTP::Session;
use uSAC::HTTP::Rex;
use uSAC::HTTP::Header qw<:constants>;
use constant MAX_READ_SIZE => 128 * 1024;

#our $LF = "\015\012";

use constant LF=>"\015\012";

###############################################################################
# sub uri_decode {                                                            #
#         my $octets= shift;                                                  #
#         $octets=~ s/\+/ /sg;                                                #
#         $octets=~ s/%([[:xdigit:]]{2})/chr(hex($1))/ge;                     #
#         return $UTF_8->decode($octets); #decode_utf8 calls this internally? #
#         #return decode_utf8($octets);                                       #
#         #return decode("utf8", $octets);                                    #
# }                                                                           #
###############################################################################
sub uri_decode_inplace {
	$_[0]=~ tr/+/ /;
	$_[0]=~ s/%([[:xdigit:]]{2})/chr(hex($1))/ge;
	#$UTF_8->decode($_[0]);
	Encode::utf8::decode $UTF_8, @_;
	#decode_utf8($_[0]);
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
use enum (qw<MODE_SERVER MODE_CLIENT>);
use enum (qw<STATE_REQUEST STATE_RESPONSE STATE_HEADERS>);

#make a reader which is bound to a session
sub make_reader{
	#take a session and alias the variables to lexicals
	my $r=shift;
	my $mode=shift; #Client or server
	#default is server mode to handle client requests
	my $start_state = $mode == MODE_CLIENT? STATE_RESPONSE : STATE_REQUEST;


	my $ex=$r->exports;
	
	\my $closeme=$ex->[0];
	my $dropper=$ex->[1];
	\my $self=$ex->[2];
	\my $rex=$ex->[3];
	weaken $r;

	my $cb=$self->current_cb;	
	my ($state,$seq) = ($start_state, 0);
	my ($method,$uri,$version,$len,$pos, $req);
	my $line;

	my %h;		#Define the header storage here, once per connection
	
	my $host;
	sub {
		\my $buf=\$_[0];
		use integer;
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
			if ($state == STATE_REQUEST) {
				my $pos3=index $buf, LF;
				
				if($pos3>=0){
					($method,$uri,$version)=split " ", substr($buf,0,$pos3);
					#$uri=uri_decode $uri;
					#uri_decode_inplace $uri;
					$uri=url_decode_utf8 $uri;
					#end of line found
						$state   = STATE_HEADERS;
						%h=();
						#++$seq;

						$buf=substr $buf, $pos3+2;
						redo;
				}
				else {
					#Exit the loop as we nee more data pushed in
					#
					if( length($buf) >2048){
						#TODO: create a rex a respond with bad request

						#$r->[uSAC::HTTP::Session::closeme_]=1;
						#$r->[uSAC::HTTP::Session::dropper_]->() 
						#$r->closeme=1;
						#$r->dropper->();
						$closeme=1;
						$dropper->();
					}
					last;
				}
			}

			elsif ($state == STATE_HEADERS) {
				# headers
				my $k;
				my $val;
				my $pos3;
				#my $index;
				while () {
					$pos3=index $buf, LF;
					if($pos3>0){
						#$index=index substr($buf,0,$pos3), ":";
						#$k=substr($buf,0,$index);
						#$val=substr($buf, $index+1,$pos3-$index);
						($k,$val)=split ":", substr($buf,0,$pos3), 2;
						#say $k,", ",$val;
						$k=~tr/-/_/;
						$k=uc $k;
						#my $val=
						$val=~tr/\t //d;
						\my $e=\$h{$k};
						$e?$e.=",$val":$e=$val;
                                                #######################################
                                                # if($e){                             #
                                                #         $e.=",$val";                #
                                                # }                                   #
                                                # else {                              #
                                                #         $e=$val;                    #
                                                #         $host=$val if $k eq "HOST"; #
                                                # }                                   #
                                                #######################################

						$host=$val if !$host and $k eq "HOST";
						$buf=substr $buf, $pos3+2;
						#redo;
					}
					elsif($pos3 == 0){
							$buf=substr($buf, $pos3+2);
							last;
					}	#empty line.

					else{
						#-1	Need more
                                                if (length($buf) > MAX_READ_SIZE) {
							
							#return $r->[uSAC::HTTP::Session::dropper_]->();
							#return $r->dropper->();
							return $dropper->();
                                                }
                                                warn "Need more";
                                                return;
					}
				}

				#Done with headers. 

				$req=uSAC::HTTP::Rex::new("uSAC::HTTP::Rex",$r, \%h, $host, $version, $method, $uri);

				$rex=$req;

				my $tmp=$h{CONNECTION}//"";
				if($version eq "HTTP/1.0"){
					$closeme=$tmp !~ /keep-alive/i;
				}
				else {

					$closeme=$tmp =~ /close/i;
				}
				

				Log::OK::DEBUG and log_debug "CLose me set to: $closeme";
				#Log::OK::DEBUG and log_debug "Reading on session: $r->[uSAC::HTTP::Session::id_]";
				Log::OK::DEBUG and log_debug "$uri";

				#shift buffer

				#$buf=substr $buf, pos $buf;# $pos;
				#
				#$pos=0;
				$state=$start_state;
				$cb->(
					$host,
					"$method $uri",
					$req
				);
				#return;

			}
			else {
			}
		} # while read
	}; # io

}


#HTML FORM readers

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


	my $state=0;
	my $first=1;
	##my %h;
	my $form_headers={};

	sub {
		\my $buf=\$_[0];
		my $processed=0;

		\my %h=$rex->headers;#[uSAC::HTTP::Rex::headers_];
		my $type = $h{CONTENT_TYPE};
		#TODO: check for content-disposition and filename if only a single part.
		my $boundary="--".(split("=", $type))[1];
		my $b_len=length $boundary;
		while($processed < length $buf){
			if($state==0){
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
						$first=1;	#reset first;
						$cb->($usac, $rex, substr($buf,$processed,$len),$form_headers,1);
						$processed+=$offset+4;
						$buf=substr $buf, $processed;
						$processed=0;
						#uSAC::HTTP::Session::pop_reader($session);
						$session->pop_reader;
						return;
					}
					else{
						#need more
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
			elsif($state==1){
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
			else{
				#say "DEFAULT";

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
	my $processed=0;					#stateful position in buffer
	my $header={};
	#Actual Reader. Uses the input buffer stored in the session. call back is also pushed
	sub {
		\my $buf=\$_[0];
		
		\my %h=$rex->headers;#[uSAC::HTTP::Rex::headers_];	#
		my $len =
		$header->{CONTENT_LENGTH}=		#copy header to part header
		$h{CONTENT_LENGTH}//0; #number of bytes to read, or 0 if undefined

		$header->{CONTENT_TYPE}=$h{CONTENT_TYPE};


		my $new=length($buf)-$processed;	#length of read buffer

		$new=$new>$len?$len:$new;		#clamp to content length
		$processed+=$new;			#track how much we have processed

		#when the remaining length is 0, pop this sub from the stack
		if($processed==$len){
			$cb->($usac, $rex, substr($buf,0,$new,""),$header,1);		#send to cb and shift buffer down
			$header={};
			$processed=0;
			$session->pod_reader;
			#uSAC::HTTP::Session::pop_reader $session;

		}
		else {
			#keep on stack until done
			$cb->($usac, $rex, substr($buf,0,$new,""),$header);		#send to cb and shift buffer down
		}

	}
}

1;
