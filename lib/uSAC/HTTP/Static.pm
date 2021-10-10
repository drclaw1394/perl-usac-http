package uSAC::HTTP::Static;

use common::sense;
use feature "refaliasing";
no warnings "experimental";
use Scalar::Util qw<weaken>;
use Devel::Peek qw<SvREFCNT>;
use Errno qw<:POSIX EACCES ENOENT>;
use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK O_RDONLY);
use Devel::Peek;
use File::Spec;
use File::Basename qw<basename dirname>;
use Cwd;
use AnyEvent;

use uSAC::HTTP::Code qw<:constants>;
use uSAC::HTTP::Header qw<:constants>;
use uSAC::HTTP::Rex;

use Errno qw<EAGAIN EINTR>;
use Exporter 'import';
our @EXPORT_OK =qw<usac_static_from send_file send_file_uri send_file_uri_range send_file_uri_norange  send_file_uri_norange_chunked send_file_uri_aio send_file_uri_sys send_file_uri_aio2 usac_dir_from usac_file_from list_dir>;
our @EXPORT=@EXPORT_OK;

use constant LF => "\015\012";
my $path_ext=	qr{\.([^.]*)$}ao;

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

sub _check_ranges{
	my ($rex, $length)=@_;
	#check for ranges in the header
	my @ranges;
	given($rex->[uSAC::HTTP::Rex::headers_]{RANGE}){
		when(undef){
			#this should be and error
			#no ranges specified but create default
			@ranges=([0,$length-1]);#$stat->[7]-1]);
		}
		default {
			#check the If-Range
			my $ifr=$rex->[uSAC::HTTP::Rex::headers_]{"IF_RANGE"};

			#check range is present
			#response code is then 206 partial
			#
			#Multiple ranges, we then return multipart doc
			my $unit;
			my $i=0;
			my $pos;	
			my $size=$length;
			given(tr/ //dr){				#Remove whitespace
				#exract unit
				$pos=index $_, "=";
				$unit= substr $_, 0, $pos++;
				my $specs= substr $_,$pos;
				
				for my $spec (split(",",$specs)){
					my ($start,$end)=split "-", $spec; #, substr($_, $pos, $pos2-$pos);
					$end||=$size-1;	#No end specified. use entire length
					unless(defined $start){
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


## Performance enhancement for slow opens
# Keeps the file handle open for other connections.
# The timer checks the ref count. When the ref count is 1, the hash is the
# only structure referencing the fileglob. Larger then 1, other sub references are 
# using it (ie reading from disk, and writing to socket)
#
# The entry is deleted if the ref count is 1. Meaning subsequent requests will cause a cache miss
# and reopen the file.
#
# Pros:
# Saves on file handles
# Improves static file delevery ALOT (around 1.5x as fast)
# Not complicated tracking of open files. Perl does it for you with ref counting
#
# Cons
# Reading from file needs to seek, as each write updates the file position
# Timer has small overhead.
#
# Random nature of hash keys means the whole set of file handles are tested, not just the first in the list.
#
# Optional sweep size to limit the time the function need to execute
#
# Gotchas:
# 	unlinking a file on disk while the filehandle is open will not prevent read/write to the file
# 	in this case when the file is close from it will finally be unlinked
#
# 	Moving a file ?
# 	
# 	Replacing a file?
#

my $open_cache ={};
my $cache_timer;
my $sweep_size=100;

sub disable_cache {
	#delete all keys
	for (keys %$open_cache){
		delete $open_cache->{$_};
	}
	$cache_timer=undef;
	
}

sub enable_cache {
	unless ($cache_timer){
		$cache_timer=AE::timer 0,10,sub {
			my $i;
			for(keys %$open_cache){
				delete $open_cache->{$_} if SvREFCNT $open_cache->{$_}[0]==1;
				last if ++$i >= $sweep_size;

			}
		};

	}

}

sub open_cache {
	my $abs_path=shift;
	say "OPEN CACHE";
	#$open_cache->{$abs_path}//do {
	#do {
		my $in_fh;
		return unless stat($abs_path) and -r _ and ! -d _; #undef if stat fails
								#or incorrect premissions


		unless(sysopen $in_fh,$abs_path,O_RDONLY|O_NONBLOCK){
			#delete $open_cache->{$abs_path};
			undef;
		}
		else {
			#lookup mime type
			#
			my $ext=substr $abs_path, rindex($abs_path, ".")+1;
			my @entry;
			$entry[1]=[HTTP_CONTENT_TYPE, ($uSAC::HTTP::Server::MIME{$ext}//$uSAC::HTTP::Server::DEFAULT_MIME)];
			$entry[0]=$in_fh;
			$entry[2]=(stat _)[7];
			$entry[3]=(stat _)[9];
			$open_cache->{$abs_path}=\@entry;
		}
		#};
}


#process without considering ranges
#This is useful for constantly chaning files and remove overhead of rendering byte range headers
sub send_file_uri_norange {
	use  integer;
	my ($matcher,$rex,$uri,$sys_root)=@_;
	my $session=$rex->[uSAC::HTTP::Rex::session_];
	\my $reply=\$session->[uSAC::HTTP::Session::wbuf_];

	my $abs_path=$sys_root."/".$uri;
	my $entry=$open_cache->{$abs_path}//open_cache $abs_path;
	
	#unless($entry=open_cache $abs_path){
	unless($entry){
		rex_reply_simple $matcher, $rex, HTTP_NOT_FOUND,[],"";
		return;
	}
	my $in_fh=$entry->[0];

	#my (undef,undef,undef,undef,undef,undef,undef,$content_length,undef,$mod_time)=stat $in_fh; 

	my ($content_length, $mod_time)=($entry->[2],$entry->[3]);
        #########################################################################
        # my ($content_length, $mod_time)=(stat $in_fh)[7,9];                   #
        #                                                                       #
        # #Do stat on fh instead of path. Path requires resolving and is slower #
        # #fh is already resolved and open.                                     #
        # unless(-r _ and !-d _){                                               #
        #         rex_reply_simple undef, $rex, HTTP_NOT_FOUND,[],"";           #
        #         #remove from cache                                            #
        #         delete $open_cache->{$abs_path};                              #
        #         return                                                        #
        # }                                                                     #
        #########################################################################


	#my ($content_length,$mod_time)=(stat _)[7,9];	#reuses stat from check_access 
	
	$reply= "$rex->[uSAC::HTTP::Rex::version_] ".HTTP_OK.LF;
	my $headers=[
		[HTTP_DATE, $uSAC::HTTP::Session::Date],
        	($session->[uSAC::HTTP::Session::closeme_]?
			[HTTP_CONNECTION, "close"]
			:([HTTP_CONNECTION, "Keep-Alive"],
			[HTTP_KEEP_ALIVE,"timeout=10, max=1000"]
			)
		),
		$entry->[1],
		[HTTP_CONTENT_LENGTH, $content_length],			#need to be length of multipart
		#.HTTP_TRANSFER_ENCODING.": chunked".LF
		[HTTP_ETAG,"\"$mod_time-$content_length\""],
		[HTTP_ACCEPT_RANGES,"bytes"]
	];

	for my $h ($rex->[uSAC::HTTP::Rex::static_headers_]->@*, $headers->@*){
		$reply.=$h->[0].": ".$h->[1].LF;
	}
	$reply.=LF;


	if($rex->[uSAC::HTTP::Rex::method_] eq "HEAD"){
		$session->[uSAC::HTTP::Session::write_]->($reply);
		return;
	}

	my $offset=length($reply);
	my $rc;
	my $total=0;

	sub {
		seek $in_fh,$total,0;
		$total+=$rc=sysread $in_fh, $reply, $read_size-$offset, $offset;

		$offset=0;
		#non zero read length.. do the write	
		if($total==$content_length){	#end of file
			$session->[uSAC::HTTP::Session::write_]->($reply);
			return;
		}

		elsif($rc){
			$session->[uSAC::HTTP::Session::write_]->($reply, __SUB__);
			return;
		}
		elsif( $! != EAGAIN and  $! != EINTR){
				say "READ ERROR from file";
				#say $rc;
				say $!;
				delete $open_cache->{$abs_path};
				close $in_fh;
				$session->[uSAC::HTTP::Session::dropper_]->();
				return;
		}

		#else {  EAGAIN }

	}->();

}

sub _html_dir_list {
	sub {
		\my $output=$_[0];
		my $headers=$_[1];
		my $entries=$_[2];

		if($headers){
			$output.=
			"<table>\n"
			."    <tr>\n"
			."        <th>".join("</th><th>",@$headers)."</th>\n"
			."    <tr>\n"
			;
		}
		if(ref $entries eq "ARRAY"){
			for my $row(@$entries){
				$output.=
				"    <tr>\n"
				."        <td>".join("</td><td>",@$row)."</td>\n"
				."    </tr>\n"
				;
			}
		}
		$output.="</table>";
	}
}

sub list_dir {
	my ($line,$rex,$uri,$sys_root,$renderer)=@_;

	my $session=$rex->[uSAC::HTTP::Rex::session_];
	\my $reply=\$session->[uSAC::HTTP::Session::wbuf_];

	my $abs_path=$sys_root."/".$uri;
	#say "Listing dir for $abs_path";
	stat $abs_path;
	unless(-d _ and  -r _){
		rex_reply_simple $line, $rex, HTTP_NOT_FOUND, [],"";
		return;
	}

	#build uri from sysroot
	my @fs_paths;
	if($abs_path eq "$sys_root/"){
	
		@fs_paths=<$abs_path*>;	
	}
	else{
		@fs_paths=<$abs_path.* $abs_path*>;	
	}

	state $labels=[qw<name dev inode mode nlink uid gid rdev size access_time modification_time change_time block_size blocks>];
	my @results=map {
		#say "WORKING ON PATH: $_";
		if(-r){			#only list items we can read
			s|^$sys_root/||;			#strip out sys_root
			my $base=(split "/")[-1].(-d _ ? "/":"");

			[qq|<a href="$rex->[uSAC::HTTP::Rex::uri_]$base">$base</a>|,stat _];
		}
		else{
			();
		}
	}

	@fs_paths;
	#say "Results ", @results;
	my $ren=$renderer//_html_dir_list;

	rex_reply_chunked $line, $rex, HTTP_OK,[] , sub {
		return unless my $writer=$_[0];			#no writer so bye

		##### Start app logic
		state $first=1;
		$reply="";					#Reset buffer
		$ren->(\$reply, $first?$labels : undef, \@results);	#Render to output
		$first=0;

		@results=();					#mark as done		
		###### End app logic
		$writer->($reply,@results? __SUB__ : undef);	#

	};
}

sub send_file_uri_norange_chunked {
	use  integer;

	my ($line,$rex,$uri,$sys_root)=@_;
	my $session=$rex->[uSAC::HTTP::Rex::session_];
	\my $reply=\$session->[uSAC::HTTP::Session::wbuf_];

	my $abs_path=$sys_root."/".$uri;

	my $entry=$open_cache->{$abs_path}//open_cache $abs_path;

	unless($entry and stat $abs_path and -r _ and !-d _){
		rex_reply_simple $line, $rex, HTTP_NOT_FOUND;
		#remove from cache
		delete $open_cache->{$abs_path};
		return
	}
	my $in_fh=$entry->[0];


	my ($content_length,$mod_time)=(stat _)[7,9];	#reuses stat from check_access 
	
	$reply=
		"$rex->[uSAC::HTTP::Rex::version_] ".HTTP_OK.LF
		#.uSAC::HTTP::Rex::STATIC_HEADERS
		.HTTP_DATE.": ".$uSAC::HTTP::Session::Date.LF
        	.($session->[uSAC::HTTP::Session::closeme_]?
			HTTP_CONNECTION.": close".LF
			:HTTP_CONNECTION.": Keep-Alive".LF
		)
		.$entry->[1]
		#.HTTP_CONTENT_LENGTH.": ".$content_length.LF			#need to be length of multipart
		.HTTP_TRANSFER_ENCODING.": chunked".LF
		.HTTP_ETAG.": \"$mod_time-$content_length\"".LF
		.HTTP_ACCEPT_RANGES.": bytes".LF
		;

	#prime the buffer by doing a read first

	#my $offset=length($reply);

	#\my $out_fh=\$session->[uSAC::HTTP::Session::fh_];
	seek $in_fh,0,0;
	my $res;
	my $rc;
	my $total=0;
        ####################################
        # #Build the required stack        #
        # uSAC::HTTP::Session::push_writer #
        #         $session,                #
        #         "http1_1_socket_writer", #
        #         undef;                   #
        ####################################

	my $chunker;

	if($rex->headers->{"ACCEPT_ENCODING"}=~/deflate/){
		#say "WILL DO GZIP";	
		$chunker=uSAC::HTTP::Session::select_writer $session, "http1_1_chunked_deflate_writer";	
		$reply.=
		HTTP_CONTENT_ENCODING.": deflate".LF
		.LF;
	}
	else{
		$chunker=uSAC::HTTP::Session::select_writer $session, "http1_1_chunked_writer";	

		$reply.=
		LF;
	}

	my $last=1;
	my $timer;
	#my $offset=length $reply;
	my $reader; $reader= sub {

		($_[0]//0) or $chunker->(undef,sub {});	#Execute stack reset
		seek $in_fh, $total, 0;
		$total+=$rc=sysread $in_fh, $reply, $read_size;#-$offset, $offset;
		
		unless($rc//0 or $! == EAGAIN or $! == EINTR){
			say "READ ERROR from file";
			say $rc;
			say $!;
			delete $open_cache->{$abs_path};
			close $in_fh;
			$reader=undef;
			#$chunker=undef;
			$session->[uSAC::HTTP::Session::dropper_]->();
			#$chunker->(undef, $reader);
			#uSAC::HTTP::Session::drop $session;
			return;
		}
		#$offset=0;
		#non zero read length.. do the write	
		if($total==$content_length){	#end of file
			$chunker->($reply);
			$reader=undef;
			return;
		}
		else{
			$chunker->($reply,$reader);
		}


		#Note: GZIP take time, so much time that the when the data is compressed
		#the socket is probably writable again. The way the writer works is it trys
		#nonblocking write before making a event listener. Potentiall this callback 
		#would never be executed based on an event, so we force it to be to prevent
		#a blocking cycle which would prevent other requests from being processed at all
		#$timer=AE::timer 0.0,0, sub { $timer=undef; $chunker->($reply, $reader)};
	};


	#write the header
	$session->[uSAC::HTTP::Session::write_]->($reply,$reader);

}


sub send_file_uri_range {
	use  integer;

	my ($route,$rex,$uri,$sys_root)=@_;
	my $session=$rex->[uSAC::HTTP::Rex::session_];
	\my $reply=\$session->[uSAC::HTTP::Session::wbuf_];

	my $abs_path=$sys_root."/".$uri;
	my $entry;
	unless($entry=open_cache $abs_path){
		rex_reply_simple $route, $rex, HTTP_NOT_FOUND,[],"";
		return;
	}
	my $in_fh=$entry->[0];

	my (undef,undef,undef,undef,undef,undef,undef,$content_length,undef,$mod_time)=stat $in_fh;#(stat _)[7,9];	#reuses stat from check_access 
	#Do stat on fh instead of path. Path requires resolving and is slower
	#fh is already resolved and open.
	unless(-r _ and !-d _){
		rex_reply_simple $route, $rex, HTTP_NOT_FOUND,[],"";
		#remove from cache
		delete $open_cache->{$uri};
		return
	}


	

	#say "CONTENT Length: $content_length";

        my @ranges=_check_ranges $rex, $content_length;
	#$,=", ";

	#say "Ranges : ",$ranges[0]->@*;
        if(@ranges==0){
                my $response=
                        "$rex->[uSAC::HTTP::Rex::version_] ".HTTP_RANGE_NOT_SATISFIABLE.LF
                        .$reply
                	.HTTP_CONTENT_RANGE.": */$content_length".LF           #TODO: Multipart had this in each part, not main header
			.HTTP_CONNECTION.": close".LF
			.LF;
			$session->[uSAC::HTTP::Session::closeme_]=1;
			$session->[uSAC::HTTP::Session::write_]->($response);
                return;
        }


	#calculate total length from ranges
	my $total_length=0;
	$total_length+=($_->[1]-$_->[0]+1) for @ranges;


	#$uri=~$path_ext;        #match results in $1;

	my $boundary="THIS_IS THE BOUNDARY";
	$reply=
		"$rex->[uSAC::HTTP::Rex::version_] ".HTTP_PARTIAL_CONTENT.LF
		#.uSAC::HTTP::Rex::STATIC_HEADERS
		.HTTP_DATE.": ".$uSAC::HTTP::Session::Date.LF
        	.($session->[uSAC::HTTP::Session::closeme_]?
			HTTP_CONNECTION.": close".LF
			:(HTTP_CONNECTION.": Keep-Alive".LF
			.HTTP_KEEP_ALIVE.": ".	"timeout=5, max=1000".LF
			)
		)
		.HTTP_ETAG.": \"$mod_time-$content_length\"".LF
		.HTTP_ACCEPT_RANGES.": bytes".LF
		.do {
			if(@ranges==1){
				HTTP_CONTENT_RANGE.": $ranges[0][0]-$ranges[0][1]/$content_length".LF
				.HTTP_CONTENT_LENGTH.": ".$total_length.LF			#need to be length of multipart
				.$entry->[1]
				#.LF
			}
			else {
				HTTP_CONTENT_TYPE.": multipart/byteranges; boundary=$boundary".LF
				#.HTTP_TRANSFER_ENCODING.": chunked".LF
				.LF
			}
		}
		;
	#TODO:
	#
	# Need to implement the chunked transfer mechanism or precalculate the
	# entire multipart length (including headers, LF etc)
	#
	# Currently only a single byte range is supported (ie no multipart)


        #setup write watcher
        my $session=$rex->[uSAC::HTTP::Rex::session_];
        \my $out_fh=\$session->[uSAC::HTTP::Session::fh_];
	
	my $state=0;#=@ranges==1?1:0;	#0 single header,1 multi header,2 data
	my $rc;

	my $index=-1;#=0;#index of current range
        my $offset;#+=length $reply; #total length
	my ($start,$end, $chunk_offset, $pos, $length);

	my $reader;$reader= sub {
		while(1){
			given($state){
				when(0){
					#say "";
					#say "Updating state"; 
					#update 
					$index++;
					$start=	$ranges[$index][0];
					$end=	$ranges[$index][1];
					$chunk_offset=0;
					$length=$end-$start+1;
					$pos=$start;

					#say "doing header";
					#normal header
					#we need to write headers
					$reply="" if $index; #reset the reply to empty stirng
					if(@ranges>1){
						$reply.=
						LF."--".$boundary.LF
						.HTTP_CONTENT_RANGE.": $ranges[$index][0]-$ranges[$index][1]/$content_length".LF
						.$entry->[1]
						.LF
					}
					else {
						$reply.=LF;
					}
					$offset=length $reply;
					$state=1;
					redo;
				}

				when(1){
					#do data
					#say "doing data";
					seek $in_fh,$pos,0 or say "Couldnot seek";
					$chunk_offset+=$rc=sysread $in_fh, $reply, $length-$chunk_offset, $offset;
					$pos+=$rc;
					#say "Range start: $start";
					#say "Range end: $end";
					#say "Range offset: $chunk_offset";
					#say "File pos: $pos";
					#say "Range length: $length";

					unless($rc//0 or $! == EAGAIN or $! == EINTR){
						say "READ ERROR from file";
						#say $rc;
						say $!;
						delete $open_cache->{$uri};
						close $in_fh;
						$reader=undef;
						#uSAC::HTTP::Session::drop $session;
						$session->[uSAC::HTTP::Session::dropper_]->();
						return;
					}
					$offset=0;
					#non zero read length.. do the write	
					if($chunk_offset==$length){	#end of file
						#add boundary
						if(@ranges==1){
							$session->[uSAC::HTTP::Session::write_]->($reply);
							return;
						}
						if($index==@ranges-1){
							#that was the last read of data .. finish
							#say "Last range, writing last boundary also";
							$reply.=LF."--".$boundary."--".LF;
							$state=0;
							$session->[uSAC::HTTP::Session::write_]->($reply);
							$reader=undef;
						}
						else{
							#more ranges to follow
							#say "End of range. writing boundary";
							#$reply=LF;#."--".$boundary.LF;
							$state=0;
							$session->[uSAC::HTTP::Session::write_]->($reply, $reader);
						}

						last;
					}

					else{
						$session->[uSAC::HTTP::Session::write_]->($reply, $reader);
						last;
					}
				}
				default {

				}
			}
		}


	};

	&$reader;#->();
}


#setup to use send file
#if $_[2] is defined, it is used as the uri,  the first capture $1 is used
#creates a path relative to the caller unless its absolute
#Similar to http paths
#
#sub static_file_from {
sub usac_static_from {
	#my %args=@_;
	#say "static file from ",@_;
	my $root=shift;#$_[0];
	my %options=@_;
	my $cache;
	if($options{cache_size}){
		$cache={}
	}


	#if the path begins with a "/"  its an absolut path
	#if it starts with "." it is processed as a relative path from the current wd
	#otherwise its a relative path relative to the callers file
		
	if($root =~ m|^[^/]|){
		#implicit path
		#make path relative to callers file
		$root=dirname((caller)[1])."/".$root;
	}

	sub {
		my $rex=$_[1];
		#my $p=$1;
		my $p;
		if($_[2]){
			$p=$_[2];
			pop;
		}	
		else {
			$p=$1;#//$rex->[uSAC::HTTP::Rex::uri_stripped_];
		}

		if($rex->[uSAC::HTTP::Rex::headers_]{RANGE}){
			send_file_uri_range @_, $p, $root;
			return;
		}
		elsif($p=~m|/$|){
			list_dir @_, $p, $root;
			return;
		}
		else{
			#Send normal
			send_file_uri_norange @_, $p, $root;
			return;
		}
	}
}
sub usac_file_from {
	#my %args=@_;
	#say "static file from ",@_;
	my $root=shift;#$_[0];
	my %options=@_;
	my $cache;
	if($options{cache_size}){
		$cache={}
	}


	#if the path begins with a "/"  its an absolut path
	#if it starts with "." it is processed as a relative path from the current wd
	#otherwise its a relative path relative to the callers file
		
	if($root =~ m|^[^/]|){
		#implicit path
		#make path relative to callers file
		$root=dirname((caller)[1])."/".$root;
	}

	sub {
		my $rex=$_[1];
		#my $p=$1;
		my $p;
		if($_[2]){
			$p=$_[2];
			pop;
		}	
		else {
			$p=$1;#//$rex->[uSAC::HTTP::Rex::uri_stripped_];
		}

		if($rex->[uSAC::HTTP::Rex::headers_]{RANGE}){
			send_file_uri_range @_, $p, $root;
			return;
		}
		else{
			#Send normal
			send_file_uri_norange @_, $p, $root;
			return;
		}
	}
}

sub usac_dir_from {
	#my %args=@_;
	#say "static file from ",@_;
	my $root=shift;#$_[0];
	my $renderer=shift;
	my %options=@_;
	my $cache;
	if($options{cache_size}){
		$cache={}
	}


	#if the path begins with a "/"  its an absolut path
	#if it starts with "." it is processed as a relative path from the current wd
	#otherwise its a relative path relative to the callers file
		
	if($root =~ m|^[^/]|){
		#implicit path
		#make path relative to callers file
		$root=dirname((caller)[1])."/".$root;
	}

	sub {
		my $rex=$_[1];
		#my $p=$1;
		my $p;
		if($_[2]){
			$p=$_[2];
			pop;
		}	
		else {
			$p=$1;#//$rex->[uSAC::HTTP::Rex::uri_stripped_];
		}
		list_dir @_, $p, $root, $renderer;
	}
}

sub send_file {
		my $rex=$_[1];
		#test for ranges
		if($rex->[uSAC::HTTP::Rex::headers_]{RANGE}){
			send_file_uri_range @_;
			return;
		}
		elsif($_[2]=~m|/$|){
			list_dir @_;
			return;
		}
		else{
			#Send normal
			send_file_uri_norange @_;
			return;
		}
	}

enable_cache;

1;
