package uSAC::HTTP::Static;

use common::sense;
use File::Spec;
use IO::AIO;
use AnyEvent::AIO;
$IO::AIO::max_parallel=1;

use Sys::Sendfile;

use uSAC::HTTP::Code qw<:constants>;
use uSAC::HTTP::Header qw<:constants>;
use uSAC::HTTP::Rex;

use Exporter 'import';
our @EXPORT_OK =qw<send_file_uri send_file_uri_aio send_file_uri_sys send_file_uri_aio2 >;
our @EXPORT=@EXPORT_OK;

use constant LF => "\015\012";
#TODO:
#add directory listing option?
sub send_file_uri_sys {
	my ($rex,$uri,$sys_root)=@_;
	state @stat;
	state $reply;

	$reply="$rex->[uSAC::HTTP::Rex::version_] ".HTTP_OK.LF
		.uSAC::HTTP::Rex::STATIC_HEADERS
		.HTTP_DATE.": ".$uSAC::HTTP::Server::Date.LF;

        #close connection after if marked
        if($rex->[uSAC::HTTP::Rex::session_][uSAC::HTTP::Server::Session::closeme_]){
                $reply.=HTTP_CONNECTION.": close".LF;

        }
	#or send explicit keep alive?
	#if($rex->[uSAC::HTTP::Rex::version_] ne "HTTP/1.1") {
	else{
		$reply.=
			HTTP_CONNECTION.": Keep-Alive".LF
			#.HTTP_KEEP_ALIVE.": timeout=5, max=1000".LF
		;
	}

	my $abs_path;
	$abs_path=$sys_root."/".$uri;
	my $offset=0;
	my $length=0;
	open(my $in_fh,"<",$abs_path) or say  "OPen error";
	my $out_fh=$rex->[uSAC::HTTP::Rex::session_][uSAC::HTTP::Server::Session::fh_];
	$length=(stat($in_fh))[7];
	$reply.=HTTP_CONTENT_LENGTH.": ".$length.LF.LF;	 		
	say "REPLY: $reply";
	$rex->[uSAC::HTTP::Rex::write_]->($reply,sub {
			say "DOING CALLBACK: offset: $offset, length: $length";
			my $res=sendfile $out_fh,$in_fh,$offset,$length;
			say "after callback: $res";
			say $! unless defined $res;
			#$rex->[uSAC::HTTP::Rex::session_]->drop;
	});

}
sub send_file_uri_aio2 {
	my ($rex,$uri,$sys_root)=@_;
	state @stat;
	state $reply;

	$reply="$rex->[uSAC::HTTP::Rex::version_] ".HTTP_OK.LF
		.uSAC::HTTP::Rex::STATIC_HEADERS
		.HTTP_DATE.": ".$uSAC::HTTP::Server::Date.LF;

        #close connection after if marked
        if($rex->[uSAC::HTTP::Rex::session_][uSAC::HTTP::Server::Session::closeme_]){
                $reply.=HTTP_CONNECTION.": close".LF;

        }
	#or send explicit keep alive?
	#if($rex->[uSAC::HTTP::Rex::version_] ne "HTTP/1.1") {
	else{
		$reply.=
			HTTP_CONNECTION.": Keep-Alive".LF
			#.HTTP_KEEP_ALIVE.": timeout=5, max=1000".LF
		;
	}

	my $abs_path;
	$abs_path=$sys_root."/".$uri;
	my $offset=0;
	my $length=0;
	open(my $in_fh,"<",$abs_path) or say  "OPen error";
	my $out_fh=$rex->[uSAC::HTTP::Rex::session_][uSAC::HTTP::Server::Session::fh_];
	$length=(stat($in_fh))[7];
	$reply.=HTTP_CONTENT_LENGTH.": ".$length.LF.LF;	 		
	my $out_fh=$rex->[uSAC::HTTP::Rex::session_][uSAC::HTTP::Server::Session::fh_];
	my $sender;
	$sender=sub {
		return unless defined $out_fh and defined $in_fh;
		aio_sendfile($out_fh,$in_fh, $offset, $length, sub {
				return unless defined $out_fh;
				return unless defined $in_fh;
				given($_[0]){
					when($_>0){
						#say $_[0];
						$offset+=$_;
						if($offset< $length){
							#say "More to send";
							$sender->();
						}
						else {
							#say "All sent";
							close $in_fh;
							$sender=undef;
							$rex->[uSAC::HTTP::Rex::session_]->drop;
						}
					}
					default{
						#say "Send file Error: $_[0]";
						#close $in_fh;
						$sender=undef;
						#say "Send file error: $!" unless $_[0];
					}
				}
			});
	};
	$rex->[uSAC::HTTP::Rex::write_]->($reply,sub {
			$sender->();
				});
		

}

sub send_file_uri_aio {
	my ($rex,$uri,$sys_root)=@_;
	state @stat;
	state $reply;

	$reply="$rex->[uSAC::HTTP::Rex::version_] ".HTTP_OK.LF
		.uSAC::HTTP::Rex::STATIC_HEADERS
		.HTTP_DATE.": ".$uSAC::HTTP::Server::Date.LF;

        #close connection after if marked
        if($rex->[uSAC::HTTP::Rex::session_][uSAC::HTTP::Server::Session::closeme_]){
                $reply.=HTTP_CONNECTION.": close".LF;

        }
	#or send explicit keep alive?
	#if($rex->[uSAC::HTTP::Rex::version_] ne "HTTP/1.1") {
	else{
		$reply.=
			HTTP_CONNECTION.": Keep-Alive".LF
			#.HTTP_KEEP_ALIVE.": timeout=5, max=1000".LF
		;
	}

	my $abs_path;
	$abs_path=$sys_root."/".$uri;
	my $offset=0;
	my $length=0;
        aio_open($abs_path, IO::AIO::O_RDONLY,0, sub {
			my $in_fh=$_[0];
			#say "Open ERROR $!" unless $_[0];
			#say "In fh: ",$in_fh;
			$length=(stat $in_fh)[7];
			#say "Length: $length";
			$reply.=HTTP_CONTENT_LENGTH.": ".$length.LF.LF;	 		
			#say $reply;
			$rex->[uSAC::HTTP::Rex::write_]->($reply,sub {
					#say "write callback";
					my $out_fh=$rex->[uSAC::HTTP::Rex::session_][uSAC::HTTP::Server::Session::fh_];
					#say "out fh: ",$out_fh;
                                        ############################################################
                                        # $rex->[uSAC::HTTP::Rex::write_]->("b" x $length, sub{    #
                                        #                 $rex->[uSAC::HTTP::Rex::session_]->drop; #
                                        #         });                                              #
                                        # return;                                                  #
                                        ############################################################
					aio_sendfile($out_fh,$in_fh, $offset, $length, sub {
							say "Send file error: $!" unless $_[0];
							close $in_fh;
							$rex->[uSAC::HTTP::Rex::session_]->drop;
						});
				})
		
	});

}

sub send_file_uri {
	my ($rex,$uri,$sys_root)=@_;
	#my $out_fh=$rex->[uSAC::HTTP::Rex::session_][uSAC::HTTP::Server::Session::fh_];
	state @stat;
	state $reply;

	$reply="$rex->[uSAC::HTTP::Rex::version_] ".HTTP_OK.LF
		.uSAC::HTTP::Rex::STATIC_HEADERS
		.HTTP_DATE.": ".$uSAC::HTTP::Server::Date.LF;

        #close connection after if marked
        if($rex->[uSAC::HTTP::Rex::session_][uSAC::HTTP::Server::Session::closeme_]){
                $reply.=HTTP_CONNECTION.": close".LF;

        }
	#or send explicit keep alive?
	#if($rex->[uSAC::HTTP::Rex::version_] ne "HTTP/1.1") {
	else{
		$reply.=
			HTTP_CONNECTION.": Keep-Alive".LF
			#.HTTP_KEEP_ALIVE.": timeout=5, max=1000".LF
		;
	}


	#open my $fh,"<",
	my $abs_path;
	$abs_path=$sys_root."/".$uri;

	#TODO: add error checking.
	my $in_fh;	
	unless (open $in_fh, "<", $abs_path){
		#error and return;
		say $!;
	}
	@stat=stat $in_fh;#$abs_path;

	#continue
	


	#$offset//=0;			#Default offset is 0
	#$length//=$stat[7]-$offset;	#Default length is remainder

	$reply.=HTTP_CONTENT_LENGTH.": ".$stat[7].LF.LF;
	#say $reply;
	local $/=undef;	
	given($rex->[uSAC::HTTP::Rex::write_]){
		$_->( $reply.<$in_fh>);
		$_->( undef ) if $rex->[uSAC::HTTP::Rex::session_][uSAC::HTTP::Server::Session::closeme_];
		$_=undef;
		${ $rex->[uSAC::HTTP::Rex::reqcount_] }--;
	}
	close $in_fh;
	
}

###########################################################################################################################################################################
# #locate and stat the the uri in one of the system roots                                                                                                                 #
# sub stat_uri{                                                                                                                                                           #
#         my ($uri,$cb,@sys_roots)=@_;                                                                                                                                    #
#         #say "Doing uri stat for $uri";                                                                                                                                 #
#                                                                                                                                                                         #
#         my $abs_path;                                                                                                                                                   #
#         my $index=0;                                                                                                                                                    #
#         my $next;                                                                                                                                                       #
#         $next=sub {                                                                                                                                                     #
#                 #say "testing index: $_[0]=> $sys_roots[$_[$_]]";                                                                                                       #
#                 $abs_path=File::Spec->rel2abs($sys_roots[$_[0]]."/".$uri);      #abs path for aio                                                                       #
#                 #say "ABS path: $abs_path";                                                                                                                             #
#                 #do stat to check file exists                                                                                                                           #
#                 aio_stat $abs_path, sub {                                                                                                                               #
#                         unless($_[0]){                                                                                                                                  #
#                                 #no error                                                                                                                               #
#                                 $next=undef;                                                                                                                            #
#                                 $cb->($abs_path);                                                                                                                       #
#                         }                                                                                                                                               #
#                         else{                                                                                                                                           #
#                                 if($index == @sys_roots){                                                                                                               #
#                                         #not found anywhere                                                                                                             #
#                                 }                                                                                                                                       #
#                                 else{                                                                                                                                   #
#                                         #try again                                                                                                                      #
#                                         $next->($index++);                                                                                                              #
#                                 }                                                                                                                                       #
#                         }                                                                                                                                               #
#                                                                                                                                                                         #
#                 };                                                                                                                                                      #
#         };                                                                                                                                                              #
#         $next->($index++);                                                                                                                                              #
# }                                                                                                                                                                       #
#                                                                                                                                                                         #
# #Do stat                                                                                                                                                                #
# #Do open                                                                                                                                                                #
# #write any                                                                                                                                                              #
#                                                                                                                                                                         #
# sub send_file_uri_sendfile{                                                                                                                                             #
#         my ($rex,$uri,$offset,$length,$cb,@sys_roots)=@_;                                                                                                               #
#         my $out_fh=$rex->[uSAC::HTTP::Rex::session_][uSAC::HTTP::Server::Session::fh_];                                                                                 #
#         my @stat;                                                                                                                                                       #
#         my $reply;                                                                                                                                                      #
#                                                                                                                                                                         #
#         $reply="$rex->[uSAC::HTTP::Rex::version_] ".HTTP_OK.LF                                                                                                          #
#                 .uSAC::HTTP::Rex::STATIC_HEADERS                                                                                                                        #
#                 .HTTP_DATE.": ".$uSAC::HTTP::Server::Date.LF;                                                                                                           #
#                                                                                                                                                                         #
#         #close connection after if marked                                                                                                                               #
#         if($rex->[uSAC::HTTP::Rex::session_][uSAC::HTTP::Server::Session::closeme_]){                                                                                   #
#                 $reply.=HTTP_CONNECTION.": close".LF;                                                                                                                   #
#                                                                                                                                                                         #
#         }                                                                                                                                                               #
#         #or send explicit keep alive?                                                                                                                                   #
#         elsif($rex->[uSAC::HTTP::Rex::version_] ne "HTTP/1.1") {                                                                                                        #
#                 $reply.=                                                                                                                                                #
#                         HTTP_CONNECTION.": Keep-Alive".LF                                                                                                               #
#                         .HTTP_KEEP_ALIVE.": timeout=5, max=1000".LF                                                                                                     #
#                 ;                                                                                                                                                       #
#         }                                                                                                                                                               #
#                                                                                                                                                                         #
#                                                                                                                                                                         #
#         #open my $fh,"<",                                                                                                                                               #
#         my $abs_path;                                                                                                                                                   #
#         for(@sys_roots){                                                                                                                                                #
#                 $abs_path=File::Spec->rel2abs($_."/".$uri);     #abs path for aio                                                                                       #
#                 @stat=stat $abs_path;                                                                                                                                   #
#                 last unless @stat;                                                                                                                                      #
#         }                                                                                                                                                               #
#                                                                                                                                                                         #
#         #TODO: do non found if no stat                                                                                                                                  #
#         my $in_fh;                                                                                                                                                      #
#         unless (open $in_fh, "<", $abs_path){                                                                                                                           #
#                 #error and return;                                                                                                                                      #
#         }                                                                                                                                                               #
#                                                                                                                                                                         #
#         #continue                                                                                                                                                       #
#                                                                                                                                                                         #
#                                                                                                                                                                         #
#                                                                                                                                                                         #
#         $offset//=0;                    #Default offset is 0                                                                                                            #
#         $length//=$stat[7]-$offset;     #Default length is remainder                                                                                                    #
#                                                                                                                                                                         #
#         $reply.=HTTP_CONTENT_LENGTH.": ".$length.LF.LF;                                                                                                                 #
#                                                                                                                                                                         #
#         $rex->[uSAC::HTTP::Rex::write_]->( $reply, sub {                                                                                                                #
#                         aio_sendfile $out_fh,$in_fh,$offset, $length, sub {                                                                                             #
#                                 $rex->[uSAC::HTTP::Rex::write_]->( undef ) if $rex->[uSAC::HTTP::Rex::session_][uSAC::HTTP::Server::Session::closeme_];                 #
#                         };                                                                                                                                              #
#                 });                                                                                                                                                     #
#                                                                                                                                                                         #
# }                                                                                                                                                                       #
# sub send_file_uri_aio {                                                                                                                                                 #
#         my ($rex,$uri,$offset,$length,$cb,@sys_roots)=@_;                                                                                                               #
#         my $fh=$rex->[uSAC::HTTP::Rex::session_][uSAC::HTTP::Server::Session::fh_];                                                                                     #
#         my $_cb ;                                                                                                                                                       #
#         my @stat;                                                                                                                                                       #
#                                                                                                                                                                         #
#         my $reply;                                                                                                                                                      #
#         $reply="$rex->[uSAC::HTTP::Rex::version_] ".HTTP_OK.LF                                                                                                          #
#                 .uSAC::HTTP::Rex::STATIC_HEADERS                                                                                                                        #
#                 .HTTP_DATE.": ".$uSAC::HTTP::Server::Date.LF;                                                                                                           #
#                                                                                                                                                                         #
#         #close connection after if marked                                                                                                                               #
#         if($rex->[uSAC::HTTP::Rex::session_][uSAC::HTTP::Server::Session::closeme_]){                                                                                   #
#                 $reply.=HTTP_CONNECTION.": close".LF;                                                                                                                   #
#                                                                                                                                                                         #
#         }                                                                                                                                                               #
#                                                                                                                                                                         #
#         #or send explicit keep alive?                                                                                                                                   #
#         elsif($rex->[uSAC::HTTP::Rex::version_] ne "HTTP/1.1") {                                                                                                        #
#                 $reply.=                                                                                                                                                #
#                         HTTP_CONNECTION.": Keep-Alive".LF                                                                                                               #
#                         .HTTP_KEEP_ALIVE.": timeout=5, max=1000".LF                                                                                                     #
#                 ;                                                                                                                                                       #
#         }                                                                                                                                                               #
#                                                                                                                                                                         #
#         #TODO: do content type look up here?                                                                                                                            #
#                                                                                                                                                                         #
#         $_cb=sub {                                                                                                                                                      #
#                 unless (defined $_[0]){                                                                                                                                 #
#                         #say "Stat error for uri";                                                                                                                      #
#                         #reply with erro                                                                                                                                #
#                         $cb->(undef);                                                                                                                                   #
#                         return;                                                                                                                                         #
#                 }                                                                                                                                                       #
#                 $_cb=undef;                                                                                                                                             #
#                 #on stat success do open                                                                                                                                #
#                 @stat=stat _;                                                                                                                                           #
#                 local $,=", ";                                                                                                                                          #
#                 #say "Stat: ", @stat;                                                                                                                                   #
#                 $offset//=0;                    #Default offset is 0                                                                                                    #
#                 $length//=$stat[7]-$offset;     #Default length is remainder                                                                                            #
#                 #say "Range start: $offset, range length: $length";                                                                                                     #
#                                                                                                                                                                         #
#                 $_cb=sub {                                                                                                                                              #
#                         #on success to send file                                                                                                                        #
#                         $_cb=undef;                                                                                                                                     #
#                         return undef unless $_[0];                                                                                                                      #
#                         my $in_fh=$_[0];                                                                                                                                #
#                         #say "open success";                                                                                                                            #
#                         #once we get here we can write headers                                                                                                          #
#                         $reply.=HTTP_CONTENT_LENGTH.": ".$length.LF.LF;                                                                                                 #
#                         my $send;                                                                                                                                       #
#                         given ($rex->[uSAC::HTTP::Rex::write_]){                                                                                                        #
#                                 $send=sub {                                                                                                                             #
#                                         aio_sendfile $fh,$in_fh,$offset, $length, sub {                                                                                 #
#                                                 $send=undef;                                                                                                            #
#                                                 #say "Send file success";                                                                                               #
#                                                 #send stats of file to originating caller                                                                               #
#                                                 #$cb->(@stat);                                                                                                          #
#                                                 $rex->[uSAC::HTTP::Rex::write_]->( undef ) if $rex->[uSAC::HTTP::Rex::session_][uSAC::HTTP::Server::Session::closeme_]; #
#                                                 #delete $self->[write_];                                                                                                #
#                                                                                                                                                                         #
#                                                 #                               $_=undef;                                                                               #
#                                                 ${ $rex->[uSAC::HTTP::Rex::reqcount_] }--;                                                                              #
#                                         };                                                                                                                              #
#                                 };                                                                                                                                      #
#                                                                                                                                                                         #
#                                 #if( $self->[write_] ) {                                                                                                                #
#                                 #say $reply;                                                                                                                            #
#                                 $rex->[uSAC::HTTP::Rex::write_]->( $reply, $send);                                                                                      #
#                         }                                                                                                                                               #
#                                                                                                                                                                         #
#                 };                                                                                                                                                      #
#                 aio_open $_[0], IO::AIO::O_RDONLY,0, $_cb;                                                                                                              #
#         };                                                                                                                                                              #
#         stat_uri $uri, $_cb, @sys_roots;                                                                                                                                #
# }                                                                                                                                                                       #
###########################################################################################################################################################################


#attempt to load file from memory cache, fall back to loaded from disk and updating cache
sub send_file_cached {

}

#open a file and map it to memory and use writev?
sub send_file_mmap {
}




1;
