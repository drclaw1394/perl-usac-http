package uSAC::HTTP::v1_1_Reader;
use common::sense;
use feature "refaliasing";
no warnings "experimental";

use Exporter 'import';

our @EXPORT_OK=qw<
		make_reader
		make_form_data_reader
		make_plain_text_reader
		make_form_urlencoded_reader
		>;

our @EXPORT=@EXPORT_OK;

use Errno qw(EAGAIN EINTR);
use AnyEvent::Util qw(WSAEWOULDBLOCK guard AF_INET6 fh_nonblocking);
use Time::HiRes qw/gettimeofday/;
use Scalar::Util 'refaddr', 'weaken';

use uSAC::HTTP::Server;
use uSAC::HTTP::Server::Session;
use constant MAX_READ_SIZE => 128 * 1024;

our $MIME;
sub DEBUG () { 0 }
our $LF = "\015\012";

#my $HEADER_QR=> qr/\G ([^:\000-\037\040]++):[\011\040]*+ ([^\012\015]*+) [\011\040]*+ \015\012/sxogca;
use constant LF=>"\015\012";
use enum (qw<STATE_REQ_LINE STATE_RES_LINE STATE_HEADERS STATE_ERROR>);

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

	my $self=$r->[uSAC::HTTP::Server::Session::server_];
	\my $buf=\$r->[uSAC::HTTP::Server::Session::rbuf_];
	\my $fh=\$r->[uSAC::HTTP::Server::Session::fh_];
	\my $write=\$r->[uSAC::HTTP::Server::Session::write_];
	#weaken $write;
	weaken $r;

	my $cb=$self->[uSAC::HTTP::Server::cb_];
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
                                #################################################################################
                                # my ($pos0,$pos1,$pos2,$pos3);                                                 #
                                # $method=substr($buf, $ixx, ($pos1=index($buf, " ", $ixx))-$ixx);              #
                                # $uri=substr($buf, ++$pos1, ($pos2=index($buf, " ", $pos1))-$pos1);            #
                                # $version=substr($buf, ++$pos2, ($pos3=index($buf, "\015\012", $pos2))-$pos2); #
                                # $line=substr($buf,$ixx,$pos3);                                                #
                                #################################################################################
				my $pos3=index $buf, LF, $ixx;
                                $line=substr($buf,$ixx,$pos3);                                                #
				$version=substr($line,-1,1)eq "1"?"HTTP/1.1":"HTTP/1.0";
				if($pos3>=0){
					#end of line found
						$state   = 1;
						$lastkey = undef;
						#Reset header information for each request	
						%h=();
						#%h = ( INTERNAL_REQUEST_ID => $id, defined $rhost ? ( Remote => $rhost, RemotePort => $rport ) : () );
						++$seq;

						$self->[uSAC::HTTP::Server::active_requests_]++;
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
					# Explicit support for multiple cookies. Possibly use seperate cookies list?
					# Treat all headers as 'list' format for this round of parsing. 
					# Understand what the continuation is supposed to achieve. Its depricated
					#  
					#warn "parse line >'".substr( $buf,pos($buf),index( $buf, "\012", pos($buf) )-pos($buf) )."'";

					if( $buf =~ /\G ([^:\000-\037\040]++):[\011\040]*+ ([^\012\015]*+) [\011\040]*+ \015\012/sxogca ){
					#if( $buf =~ /\G ([^:\000-\037\040]++)[\011\040]*+:[\011\040]*+ ([^\012\015;]*+(;)?[^\012\015]*+) \015?\012/sxogc ){
						#$lastkey = lc $1;
						\my $e=\$h{lc $1};
						#$h{ $lastkey } = exists $h{ $lastkey } ? $h{ $lastkey }.','.$2: $2;
						#$e.=','.$2 if defined $e;
						$e = defined $e ? $e.','.$2: $2;
						#say $h{ $lastkey };
                                                ########################################################################################################################
                                                # #warn "Captured header $lastkey = '$2'";                                                                             #
                                                # if ( defined $3 ) {                                                                                                  #
                                                #         pos(my $v = $2) = $-[3] - $-[2];                                                                             #
                                                #         #warn "scan ';'";                                                                                            #
                                                #         $h{ $lastkey . '+' . lc($1) } = ( defined $2 ? do { my $x = $2; $x =~ s{\\(.)}{$1}gs; $x } : $3 )            #
                                                #         while ( $v =~ m{ \G ; \s* ([^\s=]++)\s*= (?: "((?:[^\\"]++|\\.){0,4096}+)" | ([^;,\s]++) ) \s* }gcxso ); # " #
                                                #         $contstate = 1;                                                                                              #
                                                # } else {                                                                                                             #
                                                #         $contstate = 0;                                                                                              #
                                                # }                                                                                                                    #
                                                ########################################################################################################################
					}
					elsif ($buf =~ /\G\015?\012/sxogca) {
						#warn "Last line";
						last;
					}
                                        ############################################################################################################################################################
                                        # elsif ($buf =~ /\G[\011\040]+/sxogc) { # continuation                                                                                                    #
                                        #         #warn "Continuation";                                                                                                                            #
                                        #         if (length $lastkey) {                                                                                                                           #
                                        #                 $buf =~ /\G ([^\015\012;]*+(;)?[^\015\012]*+) \015?\012/sxogc or return pos($buf) = $bpos; # need more data;                             #
                                        #                 $h{ $lastkey } .= ' '.$1;                                                                                                                #
                                        #                 if ( ( defined $2 or $contstate ) ) {                                                                                                    #
                                        #                         #warn "With ;";                                                                                                                  #
                                        #                         if ( ( my $ext = index( $h{ $lastkey }, ';', rindex( $h{ $lastkey }, ',' ) + 1) ) > -1 ) {                                       #
                                        #                                 # Composite field. Need to reparse last field value (from ; after last ,)                                                #
                                        #                                 # full key rescan, because of possible case: <key:value; field="value\n\tvalue continuation"\n>                          #
                                        #                                 # regexp needed to set \G                                                                                                #
                                        #                                 pos($h{ $lastkey }) = $ext;                                                                                              #
                                        #                                 #warn "Rescan from $ext";                                                                                                #
                                        #                                 #warn("<$1><$2><$3>"),                                                                                                   #
                                        #                                 $h{ $lastkey . '+' . lc($1) } = ( defined $2 ? do { my $x = $2; $x =~ s{\\(.)}{$1}gs; $x } : $3 )                        #
                                        #                                 while ( $h{ $lastkey } =~ m{ \G ; \s* ([^\s=]++)\s*= (?: "((?:[^\\"]++|\\.){0,4096}+)" | ([^;,\s]++) ) \s* }gcxso ); # " #
                                        #                                 $contstate = 1;                                                                                                          #
                                        #                         }                                                                                                                                #
                                        #                 }                                                                                                                                        #
                                        #         }                                                                                                                                                #
                                        # }                                                                                                                                                        #
                                        ############################################################################################################################################################
					elsif($buf =~ /\G [^\012]* \Z/sxogca) {
						if (length($buf) - $ixx > $self->[uSAC::HTTP::Server::max_header_size_]) {
							$self->badconn($fh,\substr($buf, pos($buf), $ixx), "Header overflow at offset ".$pos."+".(length($buf)-$pos));
							return $r->drop( "Too big headers from rhost for request <".substr($buf, $ixx, 32)."...>");
						}
						#warn "Need more";
						return pos($buf) = $bpos; # need more data
					}
					else {
						my ($line) = $buf =~ /\G([^\015\012]++)(?:\015?\012|\Z)/sxogc;
						$self->[uSAC::HTTP::Server::active_requests_]--;
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
				$req = bless [ $version, $r, $method, $uri, \%h, $write, undef,undef,undef, \$self->[uSAC::HTTP::Server::active_requests_], $self, scalar gettimeofday() ], 'uSAC::HTTP::Rex' ;

				DEBUG && say "URI $uri";	


				$pos = pos($buf);

				$self->[uSAC::HTTP::Server::total_requests_]++;
				$r->[uSAC::HTTP::Server::Session::rex_]=$req;
				$r->[uSAC::HTTP::Server::Session::closeme_]= !( $version eq "HTTP/1.1" or $h{connection} =~/^Keep-Alive/ );

				#shift buffer
				$buf=substr $buf,$pos;
				$pos=0;
				$ixx=0;
				$state=0;
				#$self->[uSAC::HTTP::Server::cb_]($line,$req);
				$cb->($line,$req);
				weaken ($req->[1]);
				weaken( $req->[8] );
				weaken( $req->[5] );
				return;


                                #######################################################################################################################################################################################################################
                                # if (@rv) {                                                                                                                                                                                                          #
                                #         my $ref=ref $rv[0];     #test if first element is ref, or code                                                                                                                                              #
                                #         given ($ref){                                                                                                                                                                                               #
                                #                 when ( "" ) {                                                                                                                                                                                       #
                                #                         #print "NORMAL REPLY\n";                                                                                                                                                                    #
                                #                         $req->reply_simple(@rv);                                                                                                                                                                    #
                                #                 }                                                                                                                                                                                                   #
                                #                 when ('CODE') {                                                                                                                                                                                     #
                                #                         #print "CODE \n";                                                                                                                                                                           #
                                #                         $r->[uSAC::HTTP::Server::Session::on_body_] = $rv[0];                                                                                                                                       #
                                #                 }                                                                                                                                                                                                   #
                                #                 when('HASH' ) {                                                                                                                                                                                     #
                                #                         if ( $h{'content-type'}  =~ m{^                                                                                                                                                             #
                                #                                         multipart/form-data\s*;\s*                                                                                                                                                  #
                                #                                         boundary\s*=\s*                                                                                                                                                             #
                                #                                         (?:                                                                                                                                                                         #
                                #                                         "((?:[^\\"]++|\\.){0,4096})" # " quoted entry                                                                                                                               #
                                #                                         |                                                                                                                                                                           #
                                #                                         ([^;,\s]+)                                                                                                                                                                  #
                                #                                         )                                                                                                                                                                           #
                                #                                         $}xsio and exists $rv[0]{multipart}                                                                                                                                         #
                                #                         ) {                                                                                                                                                                                         #
                                #                                                                                                                                                                                                                     #
                                #                                 my $bnd = '--'.( defined $1 ? do { my $x = $1; $x =~ s{\\(.)}{$1}gs; $x } : $2 );                                                                                                   #
                                #                                 my $body = '';                                                                                                                                                                      #
                                #                                 #warn "reading multipart with boundary '$bnd'";                                                                                                                                     #
                                #                                 #warn "set on_body";                                                                                                                                                                #
                                #                                 my $cb = $rv[0]{multipart};                                                                                                                                                         #
                                #                                 $r->[uSAC::HTTP::Server::Session::on_body_] = sub {                                                                                                                                 #
                                #                                         my ($last,$part) = @_;                                                                                                                                                      #
                                #                                         if ( length($body) + length($$part) > $self->{max_body_size} ) {                                                                                                            #
                                #                                                 # TODO;                                                                                                                                                             #
                                #                                         }                                                                                                                                                                           #
                                #                                         $body .= $$part;                                                                                                                                                            #
                                #                                         #warn "Checking body '".$body."'";                                                                                                                                          #
                                #                                         my $idx = index( $body, $bnd );                                                                                                                                             #
                                #                                         while ( $idx > -1 and (                                                                                                                                                     #
                                #                                                         ( $idx + length($bnd) + 1 <= length($body) and substr($body,$idx+length($bnd),1) eq "\012" )                                                                #
                                #                                                                 or                                                                                                                                                  #
                                #                                                         ( $idx + length($bnd) + 2 <= length($body) and substr($body,$idx+length($bnd),2) eq "\015\012" )                                                            #
                                #                                                                 or                                                                                                                                                  #
                                #                                                         ( $idx + length($bnd) + 2 <= length($body) and substr($body,$idx+length($bnd),2) eq "\055\055" )                                                            #
                                #                                                 ) ) {                                                                                                                                                               #
                                #                                                 #warn "have part";                                                                                                                                                  #
                                #                                                 my $part = substr($body,$idx-2,1) eq "\015" ? substr($body,0,$idx-2) : substr($body,0,$idx-1);                                                                      #
                                #                                                 #warn Dumper $part;                                                                                                                                                 #
                                #                                                 #substr($part, 0, ( substr($part,0,1) eq "\015" ) ? 2 : 1,'');                                                                                                      #
                                #                                                 #warn "captured $idx: '$part'";                                                                                                                                     #
                                #                                                 $body = substr($body,$idx + length $bnd);                                                                                                                           #
                                #                                                 substr($body,0, ( substr($body,0,1) eq "\015" ) ? 2 : 1 ,'');                                                                                                       #
                                #                                                 #warn "body = '$body'";                                                                                                                                             #
                                #                                                 $idx = index( $body, $bnd );                                                                                                                                        #
                                #                                                 #warn "next part idx: $idx";                                                                                                                                        #
                                #                                                 length $part or next;                                                                                                                                               #
                                #                                                 #warn "Process part '$part'";                                                                                                                                       #
                                #                                                                                                                                                                                                                     #
                                #                                                 my %hd;                                                                                                                                                             #
                                #                                                 my $lk;                                                                                                                                                             #
                                #                                                 while() {                                                                                                                                                           #
                                #                                                         if( $part =~ /\G ([^:\000-\037\040]++)[\011\040]*+:[\011\040]*+ ([^\012\015;]++(;)?[^\012\015]*+) \015?\012/sxogc ){                                        #
                                #                                                                 $lk = lc $1;                                                                                                                                        #
                                #                                                                 $hd{ $lk } = exists $hd{ $lk } ? $hd{ $lk }.','.$2 : $2;                                                                                            #
                                #                                                                 if ( defined $3 ) {                                                                                                                                 #
                                #                                                                         pos(my $v = $2) = $-[3] - $-[2];                                                                                                            #
                                #                                                                         # TODO: testme                                                                                                                              #
                                #                                                                         $hd{ $lk . '+' . lc($1) } = ( defined $2 ? do { my $x = $2; $x =~ s{\\(.)}{$1}gs; $x } : $3 )                                               #
                                #                                                                         while ( $v =~ m{ \G ; \s* ([^\s=]++)\s*= (?: "((?:[^\\"]++|\\.){0,4096}+)" | ([^;,\s]++) ) \s* }gcxso ); # "                                #
                                #                                                                 }                                                                                                                                                   #
                                #                                                         }                                                                                                                                                           #
                                #                                                         elsif ($part =~ /\G[\011\040]+/sxogc and length $lk) { # continuation                                                                                       #
                                #                                                                 $part =~ /\G([^\015\012]+)\015?\012/sxogc or next;                                                                                                  #
                                #                                                                 $hd{ $lk } .= ' '.$1;                                                                                                                               #
                                #                                                                 if ( ( my $ext = index( $hd{ $lk }, ';', rindex( $hd{ $lk }, ',' ) + 1) ) > -1 ) {                                                                  #
                                #                                                                         # Composite field. Need to reparse last field value (from ; after last ,)                                                                   #
                                #                                                                         pos($hd{ $lk }) = $ext;                                                                                                                     #
                                #                                                                         $hd{ $lk . '+' . lc($1) } = ( defined $2 ? do { my $x = $2; $x =~ s{\\(.)}{$1}gs; $x } : $3 )                                               #
                                #                                                                         while ( $hd{ $lk } =~ m{ \G ; \s* ([^\s=]++)\s*= (?: "((?:[^\\"]++|\\.){0,4096}+)" | ([^;,\s]++) ) \s* }gcxso ); # "                        #
                                #                                                                 }                                                                                                                                                   #
                                #                                                         }                                                                                                                                                           #
                                #                                                         elsif ($part =~ /\G\015?\012/sxogc) {                                                                                                                       #
                                #                                                                 last;                                                                                                                                               #
                                #                                                         }                                                                                                                                                           #
                                #                                                         elsif($part =~ /\G [^\012]* \Z/sxogc) {                                                                                                                     #
                                #                                                                 # Truncated part???                                                                                                                                 #
                                #                                                                 last;                                                                                                                                               #
                                #                                                         }                                                                                                                                                           #
                                #                                                         else {                                                                                                                                                      #
                                #                                                                 pos($part) = 0;                                                                                                                                     #
                                #                                                                 last;                                                                                                                                               #
                                #                                                         }                                                                                                                                                           #
                                #                                                 }                                                                                                                                                                   #
                                #                                                 substr($part, 0,pos($part),'');                                                                                                                                     #
                                #                                                 my $enc = lc $hd{'content-transfer-encoding'};                                                                                                                      #
                                #                                                 if ( $enc eq 'quoted-printable' ) {                                                                                                                                 #
                                #                                                         require Encode;                                                                                                                                             #
                                #                                                         $MIME = Encode::find_encoding('MIME-Header');                                                                                                               #
                                #                                                         $part = $MIME->decode( $part );                                                                                                                             #
                                #                                                 }                                                                                                                                                                   #
                                #                                                                                                                                                                                                                     #
                                #                                                 elsif ( $enc eq 'base64' ) {                                                                                                                                        #
                                #                                                         require MIME::Base64;                                                                                                                                       #
                                #                                                         $part = MIME::Base64::decode_base64( $part );                                                                                                               #
                                #                                                 }                                                                                                                                                                   #
                                #                                                 $hd{filename} = $hd{'content-disposition+filename'} if exists $hd{'content-disposition+filename'};                                                                  #
                                #                                                 $hd{name}     = $hd{'content-disposition+name'}     if exists $hd{'content-disposition+name'};                                                                      #
                                #                                                 #warn "call for part $hd{name} ($last)";                                                                                                                            #
                                #                                                 $cb->( $last && $idx == -1 ? 1 : 0,$part,\%hd );                                                                                                                    #
                                #                                         }                                                                                                                                                                           #
                                #                                         #warn "just return";                                                                                                                                                        #
                                #                                         #if ($last) {                                                                                                                                                               #
                                #                                         #warn "leave with $body";                                                                                                                                                   #
                                #                                         #}                                                                                                                                                                          #
                                #                                 };                                                                                                                                                                                  #
                                #                         }                                                                                                                                                                                           #
                                #                         #                                                                               elsif ( $h{'content-type'} =~ m{^application/x-www-form-urlencoded(?:\Z|\s*;)}i and exists $rv[0]{form} ) { #
                                #                                                                                                                                                                                                                     #
                                #                         elsif (  exists $rv[0]{form} ) {                                                                                                                                                            #
                                #                                 my $body = '';                                                                                                                                                                      #
                                #                                 $r->[uSAC::HTTP::Server::Session::on_body_] = sub {                                                                                                                                 #
                                #                                         my ($last,$part) = @_;                                                                                                                                                      #
                                #                                         if ( length($body) + length($$part) > $self->{max_body_size} ) {                                                                                                            #
                                #                                                 # TODO;                                                                                                                                                             #
                                #                                         }                                                                                                                                                                           #
                                #                                         $body .= $$part;                                                                                                                                                            #
                                #                                         if ($last) {                                                                                                                                                                #
                                #                                                 $rv[0]{form}( $req->form($body), $body );                                                                                                                           #
                                #                                                 delete $r->[uSAC::HTTP::Server::Session::on_body_];                                                                                                                 #
                                #                                         }                                                                                                                                                                           #
                                #                                 };                                                                                                                                                                                  #
                                #                         }                                                                                                                                                                                           #
                                #                         elsif( exists $rv[0]{raw} ) {                                                                                                                                                               #
                                #                                 $r->[uSAC::HTTP::Server::Session::on_body_] = $rv[0]{raw};                                                                                                                          #
                                #                         }                                                                                                                                                                                           #
                                #                         else {                                                                                                                                                                                      #
                                #                                 die "XXX";                                                                                                                                                                          #
                                #                         }                                                                                                                                                                                           #
                                #                 }                                                                                                                                                                                                   #
                                #                 #TODO: Convert this to system send file                                                                                                                                                             #
                                #                 when('HANDLE') {                                                                                                                                                                                    #
                                #                         delete $r->[uSAC::HTTP::Server::Session::rw_];                                                                                                                                              #
                                #                         my $h = AnyEvent::Handle->new(                                                                                                                                                              #
                                #                                 fh => $fh,                                                                                                                                                                          #
                                #                         );                                                                                                                                                                                          #
                                #                         $h->{rbuf} = substr($buf,$pos);                                                                                                                                                             #
                                #                         #warn "creating handle ".Dumper $h->{rbuf};                                                                                                                                                 #
                                #                         $req->[3] = sub {                                                                                                                                                                           #
                                #                                 my $rbuf = shift;                                                                                                                                                                   #
                                #                                 if (defined $$rbuf) {                                                                                                                                                               #
                                #                                         if ($h) {                                                                                                                                                                   #
                                #                                                 $h->push_write( $$rbuf );                                                                                                                                           #
                                #                                         }                                                                                                                                                                           #
                                #                                         else {                                                                                                                                                                      #
                                #                                                 warn "Requested write '$$rbuf' on destroyed handle";                                                                                                                #
                                #                                         }                                                                                                                                                                           #
                                #                                 } else {                                                                                                                                                                            #
                                #                                         if ($h) {                                                                                                                                                                   #
                                #                                                 $h->push_shutdown;                                                                                                                                                  #
                                #                                                 $h->on_drain(sub {                                                                                                                                                  #
                                #                                                                 $h->destroy;                                                                                                                                        #
                                #                                                                 undef $h;                                                                                                                                           #
                                #                                                                 $r->drop() if $self;                                                                                                                                #
                                #                                                         });                                                                                                                                                         #
                                #                                                 undef $h;                                                                                                                                                           #
                                #                                         }                                                                                                                                                                           #
                                #                                         else {                                                                                                                                                                      #
                                #                                                 $r->drop() if $self;                                                                                                                                                #
                                #                                         }                                                                                                                                                                           #
                                #                                 }                                                                                                                                                                                   #
                                #                         };                                                                                                                                                                                          #
                                #                         weaken($req->[11] = $h);                                                                                                                                                                    #
                                #                         $rv[1]->($h);                                                                                                                                                                               #
                                #                         weaken($req);                                                                                                                                                                               #
                                #                         @$r = ( );                                                                                                                                                                                  #
                                #                         return;                                                                                                                                                                                     #
                                #                 }                                                                                                                                                                                                   #
                                #                 default{                                                                                                                                                                                            #
                                #                         #warn "Other rv";                                                                                                                                                                           #
                                #                 }                                                                                                                                                                                                   #
                                #         }                                                                                                                                                                                                           #
                                # }                                                                                                                                                                                                                   #
                                # weaken($req);                                                                                                                                                                                                       #
                                #                                                                                                                                                                                                                     #
                                #                                                                                                                                                                                                                     #
                                # if( $len = $h{'content-length'} ) {                                                                                                                                                                                 #
                                #         #warn "have clen";                                                                                                                                                                                          #
                                #         if ( length($buf) - $pos == $len ) {                                                                                                                                                                        #
                                #                 #warn "Equally";                                                                                                                                                                                    #
                                #                 $r->[uSAC::HTTP::Server::Session::on_body_] && (delete $r->[uSAC::HTTP::Server::Session::on_body_])->( 1, \(substr($buf,$pos)) );                                                                   #
                                #                 $buf = '';$state = $ixx = 0;                                                                                                                                                                        #
                                #                 #TEST && test_visited("finish:complete content length")                                                                                                                                             #
                                #                 # FINISHED                                                                                                                                                                                          #
                                #                 #warn "1. finished request" . Dumper $req;                                                                                                                                                          #
                                #                 return;                                                                                                                                                                                             #
                                #         }                                                                                                                                                                                                           #
                                #         elsif ( length($buf) - $pos > $len ) {                                                                                                                                                                      #
                                #                 #warn "Complete body + trailing (".( length($buf) - $pos - $len )." bytes: ".substr( $buf,$pos + $len ).")";                                                                                        #
                                #                 $r->[uSAC::HTTP::Server::Session::on_body_] && (delete $r->[uSAC::HTTP::Server::Session::on_body_])->( 1, \(substr($buf,$pos,$pos+$len)) );                                                         #
                                #                 $ixx = $pos + $len;                                                                                                                                                                                 #
                                #                 $state = 0;                                                                                                                                                                                         #
                                #                 # FINISHED                                                                                                                                                                                          #
                                #                 #warn "2. finished request" . Dumper $req;                                                                                                                                                          #
                                #                 redo;                                                                                                                                                                                               #
                                #         }                                                                                                                                                                                                           #
                                #         else {                                                                                                                                                                                                      #
                                #                 #warn "Not enough body";                                                                                                                                                                            #
                                #                 $r->[uSAC::HTTP::Server::Session::left_] = $len - ( length($buf) - $pos );                                                                                                                          #
                                #                 if ($r->[uSAC::HTTP::Server::Session::on_body_]) {                                                                                                                                                  #
                                #                         $r->[uSAC::HTTP::Server::Session::on_body_]( 0, \(substr($buf,$pos)) ) if $pos < length $buf;                                                                                               #
                                #                         $state = 2;                                                                                                                                                                                 #
                                #                 } else {                                                                                                                                                                                            #
                                #                         $state = 2;                                                                                                                                                                                 #
                                #                 }                                                                                                                                                                                                   #
                                #                 $buf = ''; $ixx = 0;                                                                                                                                                                                #
                                #                 return;                                                                                                                                                                                             #
                                #         }                                                                                                                                                                                                           #
                                # }                                                                                                                                                                                                                   #
                                # #elsif (chunked) { TODO }                                                                                                                                                                                           #
                                # else {                                                                                                                                                                                                              #
                                #         #warn "No clen";                                                                                                                                                                                            #
                                #         $r->[uSAC::HTTP::Server::Session::on_body_](1,\('')) if $r->[uSAC::HTTP::Server::Session::on_body_];                                                                                                        #
                                #         # FINISHED                                                                                                                                                                                                  #
                                #         #warn "3. finished request" . Dumper($req);                                                                                                                                                                 #
                                #         #warn "pos = $pos, lbuf=".length $buf;                                                                                                                                                                      #
                                #         #return %r=() if $req->connection eq 'close';                                                                                                                                                               #
                                #         $state = 0;                                                                                                                                                                                                 #
                                #         if ($pos < length $buf) {                                                                                                                                                                                   #
                                #                 $ixx = $pos;                                                                                                                                                                                        #
                                #                 redo;                                                                                                                                                                                               #
                                #         } else {                                                                                                                                                                                                    #
                                #                 $buf = '';$state = $ixx = 0;                                                                                                                                                                        #
                                #                 return;                                                                                                                                                                                             #
                                #         }                                                                                                                                                                                                           #
                                # }                                                                                                                                                                                                                   #
                                #######################################################################################################################################################################################################################
			} # state 1
                        ###############################################################################################################################################################################################
                        # elsif ($state == 2 ) {                                                                                                                                                                      #
                        #         #warn "partial ".Dumper( $ixx, $buf, substr($buf,$ixx) );                                                                                                                           #
                        #         if (length($buf) - $ixx >= $r->[uSAC::HTTP::Server::Session::left_]) {                                                                                                              #
                        #                 #warn sprintf "complete (%d of %d)", length $buf, $r{left};                                                                                                                 #
                        #                 $r->[uSAC::HTTP::Server::Session::on_body_] && (delete $r->[uSAC::HTTP::Server::Session::on_body_])->( 1, \(substr($buf,$ixx, $r->[uSAC::HTTP::Server::Session::left_])) ); #
                        #                 $buf = substr($buf,$ixx + $r->[uSAC::HTTP::Server::Session::left_]);                                                                                                        #
                        #                 $state = $ixx = 0;                                                                                                                                                          #
                        #                 # FINISHED                                                                                                                                                                  #
                        #                 #warn "4. finished request" . Dumper $req;                                                                                                                                  #
                        #                 #return $self->drop($id) if $req->connection eq 'close';                                                                                                                    #
                        #                 #$ixx = $pos + $r{left};                                                                                                                                                    #
                        #                 #$state = 0;                                                                                                                                                                #
                        #                 redo;                                                                                                                                                                       #
                        #         } else {                                                                                                                                                                            #
                        #                 #warn sprintf "not complete (%d of %d)", length $buf, $r{left};                                                                                                             #
                        #                 $r->[uSAC::HTTP::Server::Session::on_body_] && $r->[uSAC::HTTP::Server::Session::on_body_]( 0, \(substr($buf,$ixx)) );                                                      #
                        #                 $r->[uSAC::HTTP::Server::Session::left_] -= ( length($buf) - $ixx );                                                                                                        #
                        #                 $buf = ''; $ixx = 0;                                                                                                                                                        #
                        #                 #return;                                                                                                                                                                    #
                        #                 next;                                                                                                                                                                       #
                        #         }                                                                                                                                                                                   #
                        # }                                                                                                                                                                                           #
                        ###############################################################################################################################################################################################
			else {
			}
			#state 3: discard body

			#$r{_activity} = $r{_ractivity} = AE::now;
			#$write->(\("HTTP/1.1 200 OK\r\nContent-Length:10\r\n\r\nTestTest1\n"),\undef);
		} # while read
		return unless $self and $r;
		if (defined $len) {
			if (length $buf == MAX_READ_SIZE) {
				$self->badconn($fh,\$buf,"Can't read (@{[ MAX_READ_SIZE ]}), can't consume");
				# $! = Errno::EMSGSIZE; # Errno is useless, since not calling drop
				my $content = 'Non-consumable request';
				my $str = "HTTP/1.1 400 Bad Request${LF}Connection:close${LF}Content-Type:text/plain${LF}Content-Length:".length($content)."${LF}${LF}".$content;
				$self->[uSAC::HTTP::Server::active_requests_]--;
				$write->($str);
				$write->(undef);
				return;
			}
			else {
				# $! = Errno::EPIPE;
				# This is not an error, just EOF
			}
		} 
                ##########################################################################
                # else {                                                                 #
                #         return if $! == EAGAIN or $! == EINTR or $! == WSAEWOULDBLOCK; #
                # }                                                                      #
                ##########################################################################
		$r->drop( $! ? "$!" : ());
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
	say "aasdfasdf";;
	use integer;
	my $session=shift;
	\my $buf=\$session->[uSAC::HTTP::Server::Session::rbuf_];
	\my $cb=\$session->[uSAC::HTTP::Server::Session::reader_cb_];
	\my $rex=\$session->[uSAC::HTTP::Server::Session::rex_];


	my $state=0;
	my $first=1;
	my %h;
	sub {
		say "IN FORM PARSER";
		#\my $buf=shift;#buffer from io loop
		#my $rex=shift;
		#my $cb=$session->[uSAC::HTTP::Server::Session::reader_cb_];
		my $processed=0;

		\my %h=$rex->[uSAC::HTTP::Rex::headers_];
		my $type = $h{'content-type'};
		say "content type: $type";
		#TODO: check for content-disposition and filename if only a single part.
		my $boundary="--".(split("=", $type))[1];
		say  "boundary:",$boundary;
		my $b_len=length $boundary;
		say "buffer len:", length $buf;
		say "buffer:", $buf;
		while($processed < length $buf){
			given($state){
				when(0){
					%h=();
					#Attempt to match boundary
					my $index=index($buf,$boundary,$processed);
					if($index>=0){

						say "FOUND boundary and index: $index";
						#send partial data to callback
						my $len=($index-2)-$processed;	#-2 for LF


						$cb->(substr($buf,$processed,$len),\%h) unless $first;
						$first=0;

						#move past data and boundary
						$processed+=$index+$b_len;

						#end search
						say "buffer:",substr $buf, $processed;


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
							$cb->();
							$session->pop_reader;
							return;
						}
						elsif(substr($buf,$processed,2) eq LF){
							#it wasn't last part, so move to next state
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
						$cb->(substr($buf, $processed, $len),\%h);
						$processed+=$len;
						#wait for next read now
						return;
					}

					#attempt to match extra hyphons
					#next line after boundary is content disposition

				}

				when(1){
					#read any headers
					say "READING HEADERS";
					pos($buf)=$processed;

					while (){
						if( $buf =~ /\G ([^:\000-\037\040]++):[\011\040]*+ ([^\012\015]*+) [\011\040]*+ \015\012/sxogca ){
							\my $e=\$h{lc $1};
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

							say "Buffer:",$buf;
							#headers done. setup

							#go back to state 0 and look for boundary
							$state=0;
							last;
							#process disposition
							given($h{'content-disposition'}){
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
							given($h{'content-type'}){
								when(undef){
									#not set
								}
								default {
								}
							}

							#process content type
							$h{'content-type'};


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
	my $session=shift;
	\my $buf=\$session->[uSAC::HTTP::Server::Session::rbuf_];
	\my $cb=\$session->[uSAC::HTTP::Server::Session::reader_cb_];
	\my $rex=\$session->[uSAC::HTTP::Server::Session::rex_];
	#my $maker_sub=shift;

	my $processed=0;

	#print "MAKING URLencoded reader\n";

	#$cb->(undef) and return unless $len; #Return
	sub {
        ###############################################################
        #         \my $buf=shift;#buffer from io loop                 #
        #         my $rex=shift;                                      #
        #         #my $cb=shift;                                      #
        # my $cb=$session->[uSAC::HTTP::Server::Session::reader_cb_]; #
        ###############################################################
		say "REX IN URL READER";
		\my %h=$rex->[uSAC::HTTP::Rex::headers_];
		my $len = $h{'content-length'}//0; #number of bytes to read, or 0 if undefined



		#print "INPUT BUFF TO POST READER: $buf\n";
		my $new=length($buf)-$processed;	#length of read buffer

		$new=$new>$len?$len:$new;		#clamp to content length
		$cb->(substr($buf,0,$new,""));		#send to cb and shift buffer down
		$processed+=$new;			#track how much we have processed

		#when the remaining length is 0, pop this sub from the stack
		if($processed==$len){
			$cb->(undef);
			#return to the previous 
			say "ABOUT TO POP READER";
			$session->pop_reader;	#This assumes that the normal 1.1 reader previous in the stack
		}
		else {
			#keep on stack until done
		}

	}
}

1;
