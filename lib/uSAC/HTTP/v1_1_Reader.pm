package uSAC::HTTP::v1_1_Reader;
use feature qw<fc current_sub refaliasing say state>;
use strict;
use warnings;
no warnings "experimental";
use EV;
use Log::ger;
use Log::OK;

use Exporter 'import';
use Encode qw<find_encoding decode encode decode_utf8>;
use URL::Encode::XS;
use URL::Encode qw<url_decode_utf8>;
use uSAC::HTTP::Constants;
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
use enum (qw<STATE_REQUEST STATE_RESPONSE STATE_HEADERS STATE_BODY_CONTENT STATE_BODY_CHUNKED STATE_BODY_MULTIPART STATE_ERROR>);


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
	
	#Temp variables
	my $host;
	my $tmp;
	my $pos3;
	my $k;
	my $val;
  my $code=200;
  my $payload="";

	sub {
    state $route;
    state $captures;
    my $processed=0;
    state $body_len=0;
    state $body_type;
    state $form_headers={};

    state $multi_state=0;
    state $first=1;
    ##my %h;
    $code=200;
    state $out_header=[];
    state $dummy_cb=sub {};
    unless(@_){
      Log::OK::TRACE and log_trace "PASSING ON ERROR IN HTTP parser";
      $route and $route->[1][1]($route, $rex);#, $code, $out_header, undef, undef);
      $processed=0;
      return;
    }
		\my $buf=\$_[0];

		while ( $len=length $buf) {

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
				$pos3=index $buf, CRLF;
			  $body_type=undef;	
        $body_len=0;
				if($pos3>=0){
					($method, $uri, $version)=split " ", substr($buf, 0, $pos3);
					
					if($uri and $version){
            $uri=url_decode_utf8 $uri;
            #
						#end of line found
						$state   = STATE_HEADERS;
						%h=();
						#++$seq;

						$buf=substr $buf, $pos3+2;
					}
					else {
						$state= STATE_ERROR; 
					}

					redo;
				}
				else {
					#Exit the loop as we nee more data pushed in
					#
					if( length($buf) >MAX_READ_SIZE){
						#TODO: create a rex a respond with bad request

						#$r->[uSAC::HTTP::Session::closeme_]=1;
						#$r->[uSAC::HTTP::Session::dropper_]->() 
						#$r->closeme=1;
						#$r->dropper->();
						$state=STATE_ERROR;
						redo;
						#$closeme=1;
						#$dropper->();
						
					}
					last;
				}
			}

			elsif ($state == STATE_HEADERS) {
				# headers
				#my $pos3;
				#my $index;
				while () {
					$pos3=index $buf, CRLF;
					if($pos3>0){
						($k, $val)=split ":", substr($buf, 0, $pos3), 2;
						$k=~tr/-/_/;
						$k=uc $k;

            $val=builtin::trim $val;  #perl 5.36 required

            #$val=~s/^[\t ]//g;  #Strip leading whitespace
            #$val=~s/[\t ]$//g;  #Strep trailing whitespace

						\my $e=\$h{$k};
						$e?($e.=",$val"):($e=$val);


						$host=$val if !$host and $k eq "HOST";

						#TODO what about proxied requests with X-Forwarded-for?
						#Shoult this set the host as well
						#
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
							$state=STATE_ERROR;
							redo;
							#return $dropper->();
                                                }
                                                warn "Need more";
                                                return;
					}
				}

				#Done with headers. 



				$tmp=$h{CONNECTION}//"";
				$version eq "HTTP/1.0"
					? ($closeme=$tmp !~ /keep-alive/ai)
					: ($closeme=$tmp =~ /close/ai);
				

				Log::OK::DEBUG and log_debug "Version: $version, Close me set to: $closeme";
				Log::OK::DEBUG and log_debug "$uri";

        #Find route
        ($route, $captures)=$cb->($host, "$method $uri");
        #
				$rex=uSAC::HTTP::Rex::new("uSAC::HTTP::Rex",$r, \%h, $host, $version, $method, $uri, $ex, $captures);

        #Before calling the dispatch, setup the parser to process further data.
        #Attempt to further parse the message. It is up to middleware or application
        #to reject the further processing of POST/PUT after the first 'chunk' has been parsed.

        #Push reader. 
        $processed=0; 
        $body_len = $h{CONTENT_LENGTH}//0; #number of bytes to read, or 0 if undefined
        if($body_len==0){ 
          #No body
          $state=$start_state;
          $payload="";
          $route and $route->[1][1]($route, $rex, $code, $out_header, $payload, my $cb=undef);
          $out_header=[];
        }
        else{
          $body_type = $h{CONTENT_TYPE};
          if($body_type and $body_type =~/multipart/i){
            $state=STATE_BODY_MULTIPART;
            #next;
          }
          elsif($body_len){
            $state=STATE_BODY_CONTENT;
            #next;
          }
          elsif($h{TRANSFER_ENCODING}//"" =~ /chunked/i){
            $state=STATE_BODY_CHUNKED;
            #next;
          }
        }

        #$state=$start_state;


			}
      elsif($state==STATE_BODY_CONTENT){
        #Process the body until the content length was found or last chunk found.
        #\my $buf=\$_[0];

        #\my %h=$rex->headers;
        $form_headers->{CONTENT_LENGTH}=$body_len;		#copy header to part header

        $form_headers->{CONTENT_TYPE}=$h{CONTENT_TYPE};

        #here we need to process data untill the end of the body,
        #That could mean a chunked transfer, multipart or urlencoded type data
        #
        #FIXED CONTENT LENGTH
        #if content length is available, then we process until the number of bytes
        #are completed. An undef or callback indicates final write.
        #
        #
        

        my $new=length($buf)-$processed;	#length of read buffer

        $new=$new>$body_len?$len:$new;		#clamp to content length
        $processed+=$new;			#track how much we have processed

        my $payload=substr $buf, 0, $new, "";

        if($processed==$body_len){
          #Last send
          $state=$start_state;
          $processed=0;
          $_[PAYLOAD]="";#substr $buf, 0, $new, "";
          $route and $route->[1][1]($route, $rex, $code, $out_header, [$form_headers, $payload], my $cb=undef);
        }
        else {
          $route and $route->[1][1]($route, $rex, $code, $out_header, [$form_headers, $payload], $dummy_cb);
        }

        $form_headers={};
        $out_header=[];
      }

      elsif($state==STATE_BODY_MULTIPART){

        #START MULTIPART
        #################
        #For multipart, the OUT headers are updated on each new part, with the header info
        #is filled with the part informaion.
        #New parts are detected with new header references.
        #The complete end of the request is marked with undef callback

        
        #TODO: check for content-disposition and filename if only a single part.
        my $boundary="--".(split("=", $body_type))[1];
        my $b_len=length $boundary;
        while(length $buf){

          if($multi_state==0){
            my $index=index($buf, $boundary);
            if($index>=0){


              #send partial data to callback
              my $len=($index-2);



              #test if last
              my $offset=$index+$b_len;

              if(substr($buf, $offset, 4) eq "--".CRLF){
                #Last part
                $first=1;	#reset first;
                $multi_state=0;
                $state=$start_state;
                my $data=substr($buf, 0, $len);
                $route and $route->[1][1]($route, $rex, $code, $out_header, [$form_headers, $data], my $cb=undef);
                $out_header=[];

                $buf=substr $buf, $offset+4;
              }
              elsif(substr($buf, $offset, 2) eq CRLF){
                #not last, regular part
                my $data=substr($buf, 0, $len);
                $route and $route->[1][1]($route, $rex, $code, $out_header, [$form_headers, $data], $dummy_cb) unless $first;
                $first=0;
                #move past data and boundary
                $buf=substr $buf, $offset+2;
                $multi_state=1;
                $form_headers={};
                redo;

              }
              else{
                #need more
                #return
              }

            }

            else {
              # Full boundary not found, send partial, upto boundary length
              my $len=length($buf)-$b_len;		#don't send boundary
              my $data=substr($buf, 0, $len);
              $route and $route->[1][1]($route, $rex, $code, $out_header, [$form_headers, $data], $dummy_cb);
              $buf=substr $buf, $len;
              #wait for next read now
              return;
            }

            #attempt to match extra hyphons
            #next line after boundary is content disposition

          }
          elsif($multi_state==1){
            #read any headers
            pos($buf)=0;#$processed;

            while (){
              if( $buf =~ /\G ([^:\000-\037\040]++):[\011\040]*+ ([^\012\015]*+) [\011\040]*+ \015\012/sxogca ){
                \my $e=\$form_headers->{uc $1=~tr/-/_/r};
                $e = defined $e ? $e.','.$2: $2;

                #need to split to isolate name and filename
                redo;
              }
              elsif ($buf =~ /\G\015\012/sxogca) {
                $processed=pos($buf);

                #readjust the buffer no
                $buf=substr $buf,$processed;
                $processed=0;

                #headers done. setup

                #go back to state 0 and look for boundary
                $multi_state=0;
                last;
              }
              else {

              }
            }

            #update the offset

          }
          else{

          }
          #say "End of while";
        }
        #say "End of form reader";



        #END Multipart
        ######################



        #$state=$start_state;
      }
      elsif($state==STATE_BODY_CHUNKED){
        #CHUNKED
        #If transfer encoding is chunked, then we process as a series of chunks
        #Again, an undef callback indicats a final write
        $state=$start_state;

      }
      elsif($state==STATE_ERROR){
        $body_len=0;
        $closeme=1;
        $dropper->();
      }
      else {
        #Error state
      }
    }
  };

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
########################################################################################################################################################
# sub make_form_data_reader {                                                                                                                          #
#         use integer;                                                                                                                                 #
#                                                                                                                                                      #
#         my ($usac, $rex, $code, $out_header, $payload, $cb)=@_;                                                                                      #
#         my $session=$rex->session;                                                                                                                   #
#                                                                                                                                                      #
#                                                                                                                                                      #
#         my $state=0;                                                                                                                                 #
#         my $first=1;                                                                                                                                 #
#         ##my %h;                                                                                                                                     #
#         my $form_headers={};                                                                                                                         #
#                                                                                                                                                      #
#         sub {                                                                                                                                        #
#                 \my $buf=\$_[0];                                                                                                                     #
#                 my $processed=0;                                                                                                                     #
#                                                                                                                                                      #
#                 \my %h=$rex->headers;#[uSAC::HTTP::Rex::headers_];                                                                                   #
#                 my $type = $h{CONTENT_TYPE};                                                                                                         #
#                 #TODO: check for content-disposition and filename if only a single part.                                                             #
#                 my $boundary="--".(split("=", $type))[1];                                                                                            #
#                 my $b_len=length $boundary;                                                                                                          #
#                 say "Looking for boundary----";                                                                                                      #
#                 say "Buffer length: ". length $buf;                                                                                                  #
#                 while($processed < length $buf){                                                                                                     #
#                         say "LOOP: $processed";                                                                                                      #
#                         if($state==0){                                                                                                               #
#                                 say "STATE $state. Looking for boundary";                                                                            #
#                                 #%h=();                                                                                                              #
#                                 #Attempt to match boundary                                                                                           #
#                                 my $index=index($buf, $boundary, $processed);                                                                        #
#                                 if($index>=0){                                                                                                       #
#                                                                                                                                                      #
#                                                                                                                                                      #
#                                         say "FOUND boundary and index: $index first: $first";                                                        #
#                                         #send partial data to callback                                                                               #
#                                         my $len=($index-2)-$processed;  #-2 for LF                                                                   #
#                                                                                                                                                      #
#                                                                                                                                                      #
#                                                                                                                                                      #
#                                         #test if last                                                                                                #
#                                         my $offset=$index+$b_len;                                                                                    #
#                                         if(substr($buf, $offset, 2) eq LF){                                                                          #
#                                                 #not last                                                                                            #
#                                                 $cb->($usac, $rex, $code, $out_header, substr($buf, $processed, $len), $form_headers) unless $first; #
#                                                 $first=0;                                                                                            #
#                                                 #move past data and boundary                                                                         #
#                                                 $processed+=$offset+2;                                                                               #
#                                                 $buf=substr $buf, $processed;                                                                        #
#                                                 $processed=0;                                                                                        #
#                                                 $state=1;                                                                                            #
#                                                 $form_headers={};                                                                                    #
#                                                 redo;                                                                                                #
#                                                                                                                                                      #
#                                         }                                                                                                            #
#                                         elsif(substr($buf,$offset,4) eq "--".LF){                                                                    #
#                                                 $first=1;       #reset first;                                                                        #
#                                                 $cb->($usac, $rex, $code, $out_header, substr($buf,$processed,$len),$form_headers);                  #
#                                                 $processed+=$offset+4;                                                                               #
#                                                 $buf=substr $buf, $processed;                                                                        #
#                                                 $processed=0;                                                                                        #
#                                                 $session->pop_reader;                                                                                #
#                                                 $cb->($usac, $rex, $code, $out_header, my $a="", my $b=0);                                           #
#                                                 return;                                                                                              #
#                                         }                                                                                                            #
#                                         else{                                                                                                        #
#                                                 #need more                                                                                           #
#                                                 return                                                                                               #
#                                         }                                                                                                            #
#                                                                                                                                                      #
#                                 }                                                                                                                    #
#                                                                                                                                                      #
#                                 else {                                                                                                               #
#                                         say "NOT FOUND boundary and index: $index";                                                                  #
#                                         # Full boundary not found, send partial, upto boundary length                                                #
#                                         my $len=length($buf)-$b_len;            #don't send boundary                                                 #
#                                         $cb->($usac, $rex, $code, $out_header, substr($buf, $processed, $len),$form_headers);                        #
#                                         $processed+=$len;                                                                                            #
#                                         $buf=substr $buf, $processed;                                                                                #
#                                         $processed=0;                                                                                                #
#                                         #wait for next read now                                                                                      #
#                                         return;                                                                                                      #
#                                 }                                                                                                                    #
#                                                                                                                                                      #
#                                 #attempt to match extra hyphons                                                                                      #
#                                 #next line after boundary is content disposition                                                                     #
#                                                                                                                                                      #
#                         }                                                                                                                            #
#                         elsif($state==1){                                                                                                            #
#                                 #read any headers                                                                                                    #
#                                 say "State  $state. READING HEADERS";                                                                                #
#                                 pos($buf)=$processed;                                                                                                #
#                                                                                                                                                      #
#                                 while (){                                                                                                            #
#                                         if( $buf =~ /\G ([^:\000-\037\040]++):[\011\040]*+ ([^\012\015]*+) [\011\040]*+ \015\012/sxogca ){           #
#                                                 \my $e=\$form_headers->{uc $1=~tr/-/_/r};                                                            #
#                                                 $e = defined $e ? $e.','.$2: $2;                                                                     #
#                                                 say "Got header: $e";                                                                                #
#                                                                                                                                                      #
#                                                 #need to split to isolate name and filename                                                          #
#                                                 redo;                                                                                                #
#                                         }                                                                                                            #
#                                         elsif ($buf =~ /\G\015\012/sxogca) {                                                                         #
#                                                 say "HEADERS DONE";                                                                                  #
#                                                 $processed=pos($buf);                                                                                #
#                                                                                                                                                      #
#                                                 #readjust the buffer no                                                                              #
#                                                 $buf=substr $buf,$processed;                                                                         #
#                                                 $processed=0;                                                                                        #
#                                                                                                                                                      #
#                                                 #say "Buffer:",$buf;                                                                                 #
#                                                 #headers done. setup                                                                                 #
#                                                                                                                                                      #
#                                                 #go back to state 0 and look for boundary                                                            #
#                                                 $state=0;                                                                                            #
#                                                 last;                                                                                                #
#                                         }                                                                                                            #
#                                         else {                                                                                                       #
#                                                                                                                                                      #
#                                                 say "OTHER HEADER";                                                                                  #
#                                         }                                                                                                            #
#                                 }                                                                                                                    #
#                                                                                                                                                      #
#                                 #update the offset                                                                                                   #
#                                 #$processed=pos $buf;                                                                                                #
#                                                                                                                                                      #
#                                 say "END READING HEADER: $processed";                                                                                #
#                         }                                                                                                                            #
#                         else{                                                                                                                        #
#                                 say "DEFAULT";                                                                                                       #
#                                                                                                                                                      #
#                         }                                                                                                                            #
#                         #say "End of while";                                                                                                         #
#                 }                                                                                                                                    #
#                 #say "End of form reader";                                                                                                           #
#         }                                                                                                                                            #
#                                                                                                                                                      #
#                                                                                                                                                      #
# }                                                                                                                                                    #
########################################################################################################################################################



#This reads http1/1.1 post type 
#Headers required:
#Content-Length:  length
#Content-Type: application/x-www-form-urlencoded
#
#################################################################################################
# sub make_form_urlencoded_reader {                                                             #
#         use integer;                                                                          #
#         #These values are shared for a session                                                #
#         #                                                                                     #
#         my ($usac, $rex, $code, $out_header, $header, $cb)=@_;                                #
#         my $session=$rex->session;                                                            #
#         my $processed=0;                                        #stateful position in buffer  #
#         #my $header={};                                                                       #
#                                                                                               #
#         #NOTE: Reader HTTP Parsing chain, called from event system                            #
#         #Actual Reader. Uses the input buffer stored in the session. call back is also pushed #
#         sub {                                                                                 #
#                 \my $buf=\$_[0];                                                              #
#                                                                                               #
#                 \my %h=$rex->headers;                                                         #
#                                                                                               #
#                 my $len =                                                                     #
#                 $header->{CONTENT_LENGTH}=              #copy header to part header           #
#                 $h{CONTENT_LENGTH}//0; #number of bytes to read, or 0 if undefined            #
#                                                                                               #
#                 $header->{CONTENT_TYPE}=$h{CONTENT_TYPE};                                     #
#                                                                                               #
#                                                                                               #
#                 my $new=length($buf)-$processed;        #length of read buffer                #
#                                                                                               #
#                 $new=$new>$len?$len:$new;               #clamp to content length              #
#                 $processed+=$new;                       #track how much we have processed     #
#                                                                                               #
#                 $cb->($usac, $rex, $code, $out_header, substr($buf,0,$new,""), $header);      #
#                 if($processed==$len){                                                         #
#                         $session->pop_reader;                                                 #
#                         $processed=0;                                                         #
#                         $header=undef; #Set the header to undef for subsequent  calls         #
#                         $cb->($usac, $rex, $code, $out_header, my $a="", my $b=0);            #
#                 }                                                                             #
#                                                                                               #
#         }                                                                                     #
# }                                                                                             #
#################################################################################################

1;
