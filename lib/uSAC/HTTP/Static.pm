package uSAC::HTTP::Static;

use common::sense;
use feature "refaliasing";
no warnings "experimental";

use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK);
use File::Spec;
use IO::AIO;
use AnyEvent;
use AnyEvent::AIO;
IO::AIO::max_parallel 1;
#$IO::AIO::lkjasdf=1;

use Sys::Sendfile;

use uSAC::HTTP::Code qw<:constants>;
use uSAC::HTTP::Header qw<:constants>;
use uSAC::HTTP::Rex;

use Errno qw<EAGAIN EINTR>;
use Exporter 'import';
our @EXPORT_OK =qw<send_file_uri send_file_uri_range send_file_uri_norange  send_file_uri_aio send_file_uri_sys send_file_uri_aio2 >;
our @EXPORT=@EXPORT_OK;

use constant LF => "\015\012";
my $path_ext=	qr{\.([^.]*)$}a;

my $read_size=4096*16;
my %stat_cache;

################################################
# Server: nginx/1.21.0                         #
# Date: Thu, 15 Jul 2021 22:55:42 GMT          #
# Content-Type: text/html                      #
# Content-Length: 612                          #
# Last-Modified: Thu, 15 Jul 2021 06:55:37 GMT #
# Connection: keep-alive                       #
# ETag: "60efdbe9-264"                         #
# Accept-Ranges: bytes                         #
################################################


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
	\my $out_fh=\$rex->[uSAC::HTTP::Rex::session_][uSAC::HTTP::Server::Session::fh_];
	fcntl $out_fh, F_SETFL, 0;#O_NONBLOCK;	#this nukes other flags... read first?
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
	my $watcher;
	$rex->[uSAC::HTTP::Rex::write_]->($reply,sub {
			#create a write watcher to trigger send file.
			$watcher=AE::io  $out_fh,1, sub {
		return unless defined $out_fh and defined $in_fh;
		aio_sendfile($out_fh,$in_fh, $offset, $length, sub {
				say "IN write watcher CALLBACK: $_[0]";
				say "EAGAIN" if $! == EAGAIN;
				say $! unless $_[0]>0;
				return if $_[0]<0;
				given($_[0]){
					when($_>0){
						#say $_[0];
						$offset+=$_;
						if($offset==$length){
							#say "All sent";
							close $in_fh;
							$watcher=undef;
							$rex->[uSAC::HTTP::Rex::session_]->drop;
						}
						#else watcher will notifiy
					}
					default{
						#check if an actual error
						return if $! == EAGAIN or $! == EINTR;
						#say "Send file Error: $_[0]";
						#actual error		
						say "sendfile WRITER ERROR: ", $!;
						$watcher=undef;
						close $in_fh;
						#say "Send file error: $!" unless $_[0];
					}
				}
			});



			};
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

sub _check_ranges{
	my ($rex, $stat)=@_;
	#check for ranges in the header
	my @ranges;
	given($rex->[uSAC::HTTP::Rex::headers_]{range}){
		when(undef){
			#no ranges specified but create default
			@ranges=([0,$stat->[7]-1]);
		}
		default {
			#check the If-Range
			my $ifr=$rex->[uSAC::HTTP::Rex::headers_]{"if-range"};

			#check rnage is present
			#response code is then 206 partial
			#
			#Multiple ranges, we then return multipart doc
			my $unit;
			my $i=0;
			my $pos;	
			my $size=$stat->[7];
			given(tr/ //dr){				#Remove whitespace
				#exract unit
				$pos=index $_, "=";
				$unit= substr $_, 0, $pos++;
				for(split(",",substr($_, $pos))){

					my ($start,$end)=split "-"; #, substr($_, $pos, $pos2-$pos);
					$end||=$size-1;	#No end specified. use entire length
					unless($start){
						#no start specified. This a count, not index
						$start=$size-$end;
						$end=$size-1;
					}

					#validate range
					if(
						(0<=$start<$size) and
						(0<=$end<$size) and
						($start<=$end)
					){
						push @ranges, [$start,$end];
					}
					else {
						#416 Range Not Satisfiable
						@ranges=();
					}

				}

			}
		}
	}
	@ranges;
}

#process without considering ranges
#This is useful for constantly chaning files and remove overhead of rendering byte range headers
sub send_file_uri_norange {
	my ($line,$rex,$uri,$sys_root)=@_;
	my $abs_path=$sys_root."/".$uri;
	my $in_fh;	

	unless (open $in_fh, "<:raw", $abs_path){
		#TODO: Generate error response
		say $!;
	}
	my $stat=[stat $in_fh];

	my $reply;
	my $length=$stat->[7];

	$uri=~$path_ext;	#match results in $1;

	$reply=
		"$rex->[uSAC::HTTP::Rex::version_] ".HTTP_OK.LF
		.uSAC::HTTP::Rex::STATIC_HEADERS
		.HTTP_DATE.": ".$uSAC::HTTP::Server::Date.LF
        	.($rex->[uSAC::HTTP::Rex::session_][uSAC::HTTP::Server::Session::closeme_]?
			HTTP_CONNECTION.": close".LF
			:HTTP_CONNECTION.": Keep-Alive".LF
		)
		.HTTP_CONTENT_TYPE.": ".($uSAC::HTTP::Server::MIME{$1}//$uSAC::HTTP::Server::DEFAULT_MIME).LF
		.HTTP_CONTENT_LENGTH.": ".$length.LF			#need to be length of multipart
		.HTTP_ETAG.": ".$stat->[9]."-".$length.LF
		.LF;

	#prime the buffer by doing a read first
	my $read_total=0;
	my $write_total=0;


	$length+=length $reply;	#total length	

	#setup write watcher
	my $ww;
	my $session=$rex->[uSAC::HTTP::Rex::session_];
	\my $out_fh=\$session->[uSAC::HTTP::Server::Session::fh_];
	#this is single part response
	$ww = AE::io $out_fh, 1, sub {

		if(length($reply)< $read_size and $read_total<$length){
			given(sysread $in_fh, $reply,$read_size, length $reply){
				when($_>0){
					#write to socket
					$read_total+=$_;
				}
				when(0){
					#end of file. should not get here
				}
				when (undef){
					#error
					#drop
					$ww=undef;
					close $in_fh;
					uSAC::HTTP::Server::Session::drop $session;
					$session=undef;
				}
			}
		}
		given(syswrite $out_fh,$reply){
			when($_>0){
				$write_total+=$_;
				$reply=substr $reply, $_;
				if($write_total==$length){
					#finished
					#drop
					$ww=undef;
					close $in_fh;

					uSAC::HTTP::Server::Session::drop $session;
					$session=undef;
				}
			}
			when(0){
				#say "EOF WRITE";
				#end of file
				#drop
				$ww=undef;
				close $in_fh;
				uSAC::HTTP::Server::Session::drop $session;
					$session=undef;

			}
			when(undef){
				#error
				#say "WRITE ERROR: ", $!;
				unless( $! == EAGAIN or $! == EINTR){
					#say $!;
					$ww=undef;
					close $in_fh;
					uSAC::HTTP::Server::Session::drop $session;
					$session=undef;
					return;
				}
			}
		}
	};

}

sub send_file_uri_range {
        my ($line,$rex,$uri,$sys_root)=@_;
        my $abs_path=$sys_root."/".$uri;
        my $in_fh;
	my $session=$rex->[uSAC::HTTP::Rex::session_];
        my $response= "$rex->[uSAC::HTTP::Rex::version_] ".HTTP_OK.LF; #response line

        my ($start,$end);
        my $reply= uSAC::HTTP::Rex::STATIC_HEADERS
                .HTTP_DATE.": ".$uSAC::HTTP::Server::Date.LF
		;

        unless (open $in_fh, "<", $abs_path){
                #TODO: Generate error response
                # forbidden? not found?
                $response=
                        "$rex->[uSAC::HTTP::Rex::version_] ".HTTP_FORBIDDEN.LF
                        .$reply
			.HTTP_CONNECTION.": close".LF
			.LF;

			uSAC::HTTP::Server::Session::push_writer 
				$session,
				"http1_1_default_writer",
				undef;
			$session->[uSAC::HTTP::Server::Session::closeme_]=1;
			$session->[uSAC::HTTP::Server::Session::write_]->($response);
			uSAC::HTTP::Server::Session::drop $session;
                return;

        }
        my $stat=[stat $in_fh];

	my $total=$stat->[7];

        my @ranges=_check_ranges $rex, $stat;
        if(@ranges==0){
                $response=
                        "$rex->[uSAC::HTTP::Rex::version_] ".HTTP_RANGE_NOT_SATISFIABLE.LF
                        .$reply
                	.HTTP_CONTENT_RANGE.": */$total".LF           #TODO: Multipart had this in each part, not main header
			.HTTP_CONNECTION.": close".LF
			.LF;

			uSAC::HTTP::Server::Session::push_writer 
				$session,
				"http1_1_default_writer",
				undef;
			$session->[uSAC::HTTP::Server::Session::closeme_]=1;
			$session->[uSAC::HTTP::Server::Session::write_]->($response);
			uSAC::HTTP::Server::Session::drop $session;
                return;
        }


	#calculate total length from ranges
	my $content_length=0;
	$content_length+=($_[1]-$_[0]+1) for @ranges;

        #The following only returns the whole file in the reply;
        $start=$ranges[0][0];
        $end=$ranges[0][1];
        $total=$stat->[7];
        my $length=$end-$start+1;#$stat->[7];#(stat $in_fh)[7];#$abs_path;
        seek $in_fh,$start,0;

        $uri=~$path_ext;        #match results in $1;

	my $boundary="THIS_IS THE BOUNDARY";
        $reply=
                HTTP_CONTENT_TYPE.": multipart/byteranges; boundary=$boundary".LF
                .HTTP_CONTENT_LENGTH.": ".$content_length.LF                    #need to be length of multipart
                .HTTP_ACCEPT_RANGES.": bytes".LF
                .HTTP_ETAG.": ".$stat->[9]."-".$length.LF
                .LF
		.$boundary.LF
		.LF;

		#.HTTP_CONTENT_RANGE.": $start-$end/$total".LF           #TODO: Multipart had this in each part, not main header
		#HTTP_CONTENT_TYPE.": ".($uSAC::HTTP::Server::MIME{$1}//$uSAC::HTTP::Server::DEFAULT_MIME).LF
        #prime the buffer by doing a read first
        my $read_total=0;
        my $write_total=0;


	my $index=0;#index of current range

        $length+=length $reply; #total length

        #setup write watcher
        my $ww;
        my $session=$rex->[uSAC::HTTP::Rex::session_];
        \my $out_fh=\$session->[uSAC::HTTP::Server::Session::fh_];
        #this is single part response
        $ww = AE::io $out_fh, 1, sub {

                if(length($reply)< $read_size and $read_total<$length){
                        given(sysread $in_fh, $reply,$read_size, length $reply){
                                when($_>0){
                                        #write to socket
                                        $read_total+=$_;
                                }
                                when(0){
                                        #end of file. should not get here
                                }
                                when (undef){
                                        #error
                                        #drop
                                        $ww=undef;
                                        close $in_fh;
                                        uSAC::HTTP::Server::Session::drop $session;
                                        $session=undef;
                                }
                        }
                }
                given(syswrite $out_fh,$reply){
                        when($_>0){
                                $write_total+=$_;
                                $reply=substr $reply, $_;
                                if($write_total==$length){
                                        #finished
                                        #drop
                                        $ww=undef;
                                        close $in_fh;

                                        uSAC::HTTP::Server::Session::drop $session;
                                        $session=undef;
                                }
                        }
                        when(0){
                                #say "EOF WRITE";
                                #end of file
                                #drop
                                $ww=undef;
                                close $in_fh;
                                uSAC::HTTP::Server::Session::drop $session;
                                        $session=undef;

                        }
                        when(undef){
                                #error
                                #say "WRITE ERROR: ", $!;
                                unless( $! == EAGAIN or $! == EINTR){
                                        #say $!;
                                        $ww=undef;
                                        close $in_fh;
                                        uSAC::HTTP::Server::Session::drop $session;
                                        $session=undef;
                                        return;
                                }
                        }
                }
        };
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
