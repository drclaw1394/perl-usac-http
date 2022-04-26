package uSAC::HTTP::Static;
use strict;
use warnings;

use feature qw<say  refaliasing state current_sub>;
no warnings "experimental";
use Log::ger;
use Log::OK;
use Data::Dumper;
use JSON;
#no feature "indirect";
use Devel::Peek qw<SvREFCNT>;
#use Errno qw<:POSIX EACCES ENOENT>;
use Fcntl qw(O_NONBLOCK O_RDONLY);
#use File::Spec;
use File::Basename qw<basename dirname>;
use Time::Piece;
use Cwd;
use AnyEvent;
use Sys::Sendfile;

use uSAC::HTTP::Code qw<:constants>;
use uSAC::HTTP::Header qw<:constants>;
use uSAC::HTTP::Rex;

use Errno qw<EAGAIN EINTR EBUSY>;
use Exporter 'import';
our @EXPORT_OK =qw<send_file send_file_uri send_file_uri_aio send_file_uri_sys send_file_uri_aio2 usac_file_under list_dir>;
our @EXPORT=@EXPORT_OK;

use constant LF => "\015\012";
my $path_ext=	qr{\.([^.]*)$}ao;

my $read_size=4096*16;
my %stat_cache;

use enum qw<fh_ content_type_header_ size_ mt_ last_modified_header_ content_encoding_>;
use constant KEY_OFFSET=>0;

use enum ("mime_=".KEY_OFFSET, qw<default_mime_ html_root_ cache_ cache_size_ cache_sweep_size_ cache_timer_ end_>);
use constant KET_COUNT=>end_-mime_+1;

sub new {
	my $package=shift//__PACKAGE__;
	my $self=[];	
	my %options=@_;
	my $root=$options{root};
	$self->[html_root_]=uSAC::HTTP::Site::usac_path(%options, $options{html_root});
	$self->[mime_]=$options{mime}//{};		#A mime lookup hash
	$self->[default_mime_]=$options{default_mime}//"";		#A mime type
	$self->[cache_]={};#$options{mime_lookup}//{};		#A mime lookup hash
	$self->[cache_sweep_size_]=$options{cache_sweep_size}//100;
	$self->[cache_timer_]=undef;
	$self->[cache_size_]=$options{cache_size};
	bless $self, $package;
	$self->enable_cache;
	$self;
}


#TODO:
#add directory listing option?

sub _check_ranges{
	my ($rex, $length)=@_;
	#check for ranges in the header
	my @ranges;
	for($rex->[uSAC::HTTP::Rex::headers_]{RANGE}){
		if(!defined){
			#this should be and error
			#no ranges specified but create default
			@ranges=([0,$length-1]);#$stat->[7]-1]);
		}
		else {
			#check the If-Range
			my $ifr=$rex->[uSAC::HTTP::Rex::headers_]{"IF-RANGE"};

			#check range is present
			#response code is then 206 partial
			#
			#Multiple ranges, we then return multipart doc
			my $unit;
			my $i=0;
			my $pos;	
			my $size=$length;
			for(tr/ //dr){				#Remove whitespace
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


sub disable_cache {
	my $self=shift;
	#delete all keys
	for (keys $self->[cache_]->%*){
		delete $self->[cache_]{$_};
	}
	#stop timer
	$self->[cache_timer_]=undef;
}

sub enable_cache {
	my $self=shift;
	unless ($self->[cache_timer_]){
		$self->[cache_timer_]=AE::timer 0,10,sub {
			my $i;
			for(keys $self->[cache_]->%*){
				delete $self->[cache_]{$_} if SvREFCNT $self->[cache_]{$_}[0]==1;
				last if ++$i >= $self->[cache_sweep_size_];
			}
		};
	}
}

my %encoding_map =(
	gz=>"gzip",
);

sub open_cache {
	my ($self, $abs_path, $mode, $pre_encoded)=@_;
	my $in_fh;
	my $enc_path;
	#my @search=map $abs_path.".$_", @$pre_encoded;
	#push @search, $abs_path;

	for my $pre (@$pre_encoded,""){

		my $path= $abs_path.($pre?".$pre":"");

		Log::OK::TRACE and log_trace "Static: Searching for: $path";

		next unless stat($path) and -r _ and ! -d _; #undef if stat fails
		#or incorrect premissions


		unless(sysopen $in_fh,$path,O_RDONLY|O_NONBLOCK|($mode//0)){
			#undef;
			return;
		}
		else {
			#lookup mime type
			#
			my $ext=substr $abs_path, rindex($abs_path, ".")+1;
			#next if $ext==$pre;

			my @entry;
			$entry[content_type_header_]=[HTTP_CONTENT_TYPE, ($self->[mime_]{$ext}//$self->[default_mime_])];
			$entry[fh_]=$in_fh;
			$entry[size_]=(stat _)[7];
			$entry[mt_]=(stat _)[9];
			if($pre){
				$entry[content_encoding_]=[HTTP_CONTENT_ENCODING, $encoding_map{$pre}];
			}
			else{
				$entry[content_encoding_]=[];
			}
			Log::OK::TRACE and log_trace "pre com: ".$pre;
			Log::OK::TRACE and log_trace "content encoding: ". join ", ", $entry[content_encoding_]->@*;
			my $tp=gmtime($entry[mt_]);
			$entry[last_modified_header_]=[HTTP_LAST_MODIFIED, $tp->strftime("%a, %d %b %Y %T GMT")];
			return $self->[cache_]{$abs_path}=\@entry;
		}
	}
}


#process without considering ranges
#This is useful for constantly chaning files and remove overhead of rendering byte range headers
sub send_file_uri_norange {
	#return a sub with cache an sysroot aliased
		use  integer;
		my ($matcher,$rex,$user_headers, $read_size, $sendfile, $entry, $no_encoding)=@_;
		Log::OK::TRACE and log_TRACE("send file no range");
		my $session=$rex->[uSAC::HTTP::Rex::session_];
		$session->[uSAC::HTTP::Session::in_progress_]=1;

		my $in_fh=$entry->[fh_];

		my ($content_length, $mod_time)=($entry->[size_],$entry->[mt_]);

		my $reply="";
		#process caching headers
		my $headers=$_[1][uSAC::HTTP::Rex::headers_];#$rex->headers;
		my $code=HTTP_OK;
		my $etag="\"$mod_time-$content_length\"";

		my $offset=0;#=length($reply);
		my $rc;
		my $total=0;

		my @ranges;

		#Send file
		#======
		# call sendfile. If remaining data to send, setup write watcher to 
		# trigger next call
                my $out_fh=$session->[uSAC::HTTP::Session::fh_];
		my $ww;
                my $do_sendfile;
		if($sendfile){
			$do_sendfile=sub {
				Log::OK::TRACE  and log_trace "Doing send file";
				#Do send file here?
				#seek $in_fh,$total,0;
				#in, out, size, input_offset
				$total+=$rc=sendfile($out_fh, $in_fh, $read_size, $offset);
				$offset+=$rc;

				#non zero read length.. do the write
				if($total==$content_length){    #end of file
					#Goto next range,
					if(@ranges){
						$total=0;
						my $r=shift @ranges;
						$offset=$r->[0];
						$content_length=$r->[1];
						
						#write header
						
						&__SUB__;	#restart
						return;	
					}
					#ofr drop if no more
					#Do dropper as we reached the end
					$session->[uSAC::HTTP::Session::dropper_]->();
					$out_fh=undef;
					$ww=undef;
					#$ww=undef;
					#$session->[uSAC::HTTP::Session::write_]->($reply, $session->[uSAC::HTTP::Session::dropper_]);
					return;
				}

				elsif($rc){
					#redo the sub and more data to send
					#
					
					$ww=AE::io $out_fh, 1, __SUB__ unless $ww;#$do_sendfile;
					# __SUB__->();
					#$session->[uSAC::HTTP::Session::write_]->($reply, __SUB__);
					return;
				}
				elsif( $! != EAGAIN and  $! != EINTR and $! != EBUSY){
					say "Send file error";
					#say $rc;
					say $!;
					#delete $cache{$abs_path};
					#close $in_fh;
					$session->[uSAC::HTTP::Session::dropper_]->();
					return;
				}

				else {  
					say "EAGAIN";
				}

			};
		}


		#TODO: needs testing
		for my $t ($headers->{"IF-NONE-MATCH"}){#HTTP_IF_NONE_MATCH){
			$code=HTTP_OK and last unless $t;
			$code=HTTP_OK and last if  $etag !~ /$t/;
			$code=HTTP_NOT_MODIFIED and last;	#no body to be sent

		}

		#TODO: needs testing
		for(my $time=$headers->{"IF-MODIFIED-SINCE"}){
			#attempt to parse
			$code=HTTP_OK and last unless $time;
			my $tp=Time::Piece->strptime($time, "%a, %d %b %Y %T GMT");
			$code=HTTP_OK  and last if $mod_time>$tp->epoch;
			$code=HTTP_NOT_MODIFIED;	#no body to be sent
		}
			
		#Add no compress (ie identity) if encoding is not set
		#and if no_encodingflag is set
		#

		
		my $out_headers=[
			HTTP_VARY, "Accept",
			$entry->[last_modified_header_]->@*,
			$entry->[content_type_header_]->@*,
			(!$entry->[content_encoding_]->@* and $no_encoding)
				? (HTTP_CONTENT_ENCODING, "identity")
				: $entry->[content_encoding_]->@*,

			#HTTP_CONTENT_TYPE, "text/plain",
			#HTTP_CONTENT_ENCODING, "gzip",

			HTTP_CONTENT_LENGTH, $content_length,			#need to be length of multipart
			HTTP_ETAG,$etag,
			HTTP_ACCEPT_RANGES,"bytes",
			@$user_headers


		];
		if($headers->{RANGE}){
			@ranges=_check_ranges $rex, $content_length;
			unless(@ranges){
				$code=HTTP_RANGE_NOT_SATISFIABLE;
				push @$out_headers, HTTP_CONTENT_RANGE, "*/$content_length";

				rex_write $matcher,$rex,$code,$out_headers,"";
				return;
			}
			elsif(@ranges==1){
				$code=HTTP_PARTIAL_CONTENT;
				my $total_length=0;
				$total_length+=($_->[1]-$_->[0]+1) for @ranges;
				push @$out_headers,
				HTTP_CONTENT_RANGE, "$ranges[0][0]-$ranges[0][1]/$content_length",
				HTTP_CONTENT_LENGTH, $total_length;
			}
			else{

			}
		}

		Log::OK::TRACE and log_trace join ", ", @$out_headers;
		


		if(
			$rex->[uSAC::HTTP::Rex::method_] eq "HEAD" 
			or $code==HTTP_NOT_MODIFIED
			){
			rex_write $matcher,$rex,$code,$out_headers,"";
			#$session->[uSAC::HTTP::Session::write_]->($reply);
			return;
		}

		#my $sendfile=1;
		#Enable using send file if content length is greater than threshold
		if($sendfile and $content_length>=$sendfile){
			Log::OK::TRACE  and log_trace "Writing sendfile header";
			#Write header out and then issue send file

			#Setup writable event listener

			rex_write $matcher,$rex,$code,$out_headers,"", $do_sendfile;
			#$session->[uSAC::HTTP::Session::write_]->($reply, $do_sendfile);
			return;
		}
		#else do the normal copy and write

		#Clamp the readsize to the file size if its smaller
		$read_size=$content_length if $content_length < $read_size;

		#$offset=length($reply);

                sub {
                        #NON Send file
                        seek $in_fh,$offset,0;
                        $total+=$rc=sysread $in_fh, $reply, $read_size;#, $offset;
			$offset+=$rc;

                        #non zero read length.. do the write
                        if($total==$content_length){    #end of file
				if(@ranges){
					#write and use callback
					my $sub=__SUB__;
					rex_write $matcher, $rex, $code, $out_headers, $reply, sub {
						my $r=shift @ranges;
						$offset=$r->[0];
						$total=0;
						$content_length=$r->[1];
						#write new multipart header
						$sub->();
					};

					return
				} else {
					#write and done
					rex_write $matcher,$rex,$code,$out_headers,$reply;
					return;

				}

                        }

                        elsif($rc){
				rex_write $matcher, $rex, $code, $out_headers, $reply, __SUB__;
                                return;
                        }
                        elsif( $! != EAGAIN and  $! != EINTR){
                                say "READ ERROR from file";
                                #say $rc;
                                say $!;
                                #delete $cache{$abs_path};
                                close $in_fh;
                                $session->[uSAC::HTTP::Session::dropper_]->();
                                return;
                        }

                        #else {  EAGAIN }

        }->();


}

sub _html_dir_list {
	sub {
		say "html dir list renderer";
		my $headers=$_[1];
		my $entries=$_[2];

		if($headers){
			$_[0].=
			"<table>\n"
			."    <tr>\n"
			."        <th>".join("</th><th>",@$headers)."</th>\n"
			."    <tr>\n"
			;
		}
		if(ref $entries eq "ARRAY"){
			for my $row(@$entries){
				my ($url,$label)=splice @$row,0,2;
				unshift @$row, qq|<a href="$url">$label</a>|;
				$_[0].=
				"    <tr>\n"
				."        <td>".join("</td><td>",@$row)."</td>\n"
				."    </tr>\n"
				;
			}
		}
		$_[0].="</table>";
	}
}
sub _json_dir_list {
	sub {
		state  $headers;
		if($_[1]){
			$headers=$_[1];
		}
		#build up tuples of key=value pairs
		my @tuples;
		for my $row ($_[2]->@*){
			my $trow={};
			for my $index (0..@$row-1){
				$trow->{$headers->[$index]}=$row->[$index];	
			}
			push @tuples, $trow;
		}
		$_[0].=encode_json \@tuples
	}

}

sub make_list_dir {
	my $self=shift;

	\my $html_root=\$self->[html_root_];
	\my %cache=$self->[cache_];
	my %options=@_;
	my $renderer=$options{renderer};
	my @type;
	#resolve renderer
	if( !defined $renderer){
		$renderer=&_html_dir_list;
		@type=(HTTP_CONTENT_TYPE, "text/html");
	}
	elsif(lc $renderer eq "html"){
		$renderer=&_html_dir_list;
		@type=(HTTP_CONTENT_TYPE, "text/html");
	}
	elsif(lc $renderer eq "json"){
		$renderer= &_json_dir_list;
		@type=(HTTP_CONTENT_TYPE, "text/json");
	}
	else {
		$renderer=!defined $renderer? &_html_dir_list: $renderer;
		@type=(HTTP_CONTENT_TYPE, "text/html");
	}
	
	sub{
		my ($line,$rex,$uri)=@_;
		my $session=$rex->[uSAC::HTTP::Rex::session_];

		my $abs_path=$html_root.$uri;
		stat $abs_path;
		unless(-d _ and  -r _){
			rex_error_not_found $line, $rex;
			#rex_write $line, $rex, HTTP_NOT_FOUND, {},"";
			return;
		}

		#build uri from sysroot
		my @fs_paths;
		say  "ABS PATH $abs_path";
		if($abs_path eq "$html_root/"){

			@fs_paths=<$abs_path*>;	
		}
		else{
			@fs_paths=<$abs_path.* $abs_path*>;	
		}
		state $labels=[qw<name dev inode mode nlink uid gid rdev size access_time modification_time change_time block_size blocks>];
		my @results
                        =map {
                        #if(-r){                        #only list items we can read
                                my $isDir= -d;
                                s|^$html_root/||;                       #strip out html_root
                                my $base=(split "/")[-1].($isDir? "/":"");

                                ["$rex->[uSAC::HTTP::Rex::uri_]$base", $base, stat _]
                }
		@fs_paths;
		my $ren=$renderer//&_html_dir_list;

		my $data="";#"lkjasdlfkjasldkfjaslkdjflasdjflaksdjf";
		$ren->($data, $labels, \@results);	#Render to output
		rex_write $line, $rex, HTTP_OK,[HTTP_CONTENT_LENGTH, length $data, @type] , $data;
	}
}


sub send_file_uri_range {
		use  integer;

		my ($route,$rex,$entry)=@_;
		my $session=$rex->[uSAC::HTTP::Rex::session_];

		my $in_fh=$entry->[fh_];

		my ($content_length, $mod_time)=($entry->[size_],$entry->[mt_]);
		#my (undef,undef,undef,undef,undef,undef,undef,$content_length,undef,$mod_time)=stat $in_fh;#(stat _)[7,9];	#reuses stat from check_access 



		my @ranges=_check_ranges $rex, $content_length;
		#$,=", ";

		if(@ranges==0){
			my $response=
			"$rex->[uSAC::HTTP::Rex::version_] ".HTTP_RANGE_NOT_SATISFIABLE.LF
			#.$reply
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
		my $reply=
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
				.HTTP_CONTENT_TYPE.":".$entry->[content_type_header_][1]
				.LF
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
		#my $session=$rex->[uSAC::HTTP::Rex::session_];
		\my $out_fh=\$session->[uSAC::HTTP::Session::fh_];

		my $state=0;#=@ranges==1?1:0;	#0 single header,1 multi header,2 data
		my $rc;

		my $index=-1;#=0;#index of current range
		my $offset;#+=length $reply; #total length
		my ($start,$end, $chunk_offset, $pos, $length);

		my $reader;$reader= sub {
			while(1){
				for($state){
					if($_ eq 0){
						#update 
						$index++;
						$start=	$ranges[$index][0];
						$end=	$ranges[$index][1];
						$chunk_offset=0;
						$length=$end-$start+1;
						$pos=$start;

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

					elsif($_ == 1){
						#do data
						seek $in_fh,$pos,0 or say "Couldnot seek";
						$chunk_offset+=$rc=sysread $in_fh, $reply, $length-$chunk_offset, $offset;
						$pos+=$rc;

						unless($rc//0 or $! == EAGAIN or $! == EINTR){
							say "READ ERROR from file";
							say $!;
							#delete $self->[cache_]{$uri};
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
								$session->[uSAC::HTTP::Session::write_]->($reply, $session->[uSAC::HTTP::Session::dropper_]);
								return;
							}
							if($index==@ranges-1){
								#that was the last read of data .. finish
								$reply.=LF."--".$boundary."--".LF;
								$state=0;
								$session->[uSAC::HTTP::Session::write_]->($reply);
								$reader=undef;
							}
							else{
								#more ranges to follow
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
					else{

					}
				}
			}
		};
		&$reader;#->();
}



#Server static files under the specified root dir
#Dual mode. Also acts as innerware

#Specifies the url prefix (and or regex) to match
#The prefix is removed and
sub usac_file_under {
	#create a new static file object
	#my $parent=$_;
	my $html_root=pop;
	my %options=@_;
	my $parent=$options{parent}//$uSAC::HTTP::Site;

	$options{mime}=$parent->resolve_mime_lookup;
	$options{default_mime}=$parent->resolve_mime_default;

	my $headers=$options{headers}//[];
	my $read_size=$options{read_size}//$read_size;
	my $sendfile=$options{sendfile}//0;
	my $open_modes=$options{open_flags}//0;
	my $filter=$options{filter};
	my $no_encoding=$options{no_encoding};
	my $do_dir=$options{list_dir}//$options{do_dir};
	my $pre_encoded=$options{pre_encoded}//[];
	Log::OK::TRACE and log_trace "OPTIONS IN: ".join ", ", %options;
	my $static=uSAC::HTTP::Static->new(html_root=>$html_root, %options);

	\my @indexes=$options{indexes}//[];
	my $cache=$static->[cache_];
	$html_root=$static->[html_root_];
	my $list_dir=$static->make_list_dir(%options);

	die "Can not access dir $html_root to serve static files" unless -d $html_root;
	#check for mime type in parent 

	#create the sub to use the static files here
	sub {
		#Do a check here. if first argment is a sub ref we are being used as middleware
		#But this should only happen once.
		state $next;
		if(!$next and ref($_[0])eq "CODE"){
		
				$next=$_[0];
				Log::OK::TRACE and log_trace "Static file: returning  middle ware";
				return __SUB__;
		}
			
		

		#matcher, rex, code, headers, uri if not in $_
		my $rex=$_[1];
		#my $p=$1;
		my $p;
		if($_[2]){

			Log::OK::TRACE and log_trace "Static: Input uri: ". $rex->[uSAC::HTTP::Rex::uri_stripped_];
			$p=$_[2];
			pop;
		}	
		else {
			#$p=&rex_capture->[0];#$1;#//$rex->[uSAC::HTTP::Rex::uri_stripped_];
			Log::OK::TRACE and log_trace "Static: Stripped uri: ". $rex->[uSAC::HTTP::Rex::uri_stripped_];
			#$p=$_[1][uSAC::HTTP::Rex::capture_][0];
			$p=$rex->[uSAC::HTTP::Rex::uri_stripped_];
		}

		
		my $path=$html_root.$p;
		if($filter and $path !~ /$filter/o){
			return &$next if $next;
			
			&rex_error_not_found;
			return 1;
		}

		#If compress option is enabled then do not set the content-encoding header
		#Otherwise we set to identity
		#check that the requested file matches the the pre compressed 
		#

		#
		my @head=@$headers;
                ##########################################################################
                # if($no_compress and $path =~ /$no_compress/o){                         #
                #         Log::OK::TRACE and log_trace "Setting identity content encoding"; #
                #         push @head, HTTP_CONTENT_ENCODING, "identity";                 #
                # }                                                                      #
                ##########################################################################
		#Ensure we don't attempt to test gz files
		$pre_encoded=[] if $path=~/gz/ or $_[1]->headers->{ACCEPT_ENCODING}//"" !~ /gzip/;		#GZIP is supporte

		Log::OK::TRACE and log_trace "static: html_root: $html_root";



		#Server dir listing if option is specified
		#
		#=========================================
		
		if($do_dir || @indexes and $path =~ m|/$|){
			#attempt to do automatic index file.
			my $entry;
			for(@indexes){
				my $path=$html_root.$p.$_;
				Log::OK::TRACE and log_trace "Static: Index searching PATH: $path";
				$entry=$cache->{$path}//$static->open_cache($path);
				next unless $entry;
				if($rex->[uSAC::HTTP::Rex::headers_]{RANGE}){
					send_file_uri_range @_, $entry;
					return;
				}
				else{
					#Send normal
					#$static->send_file_uri_norange(@_, $p, $root);
					send_file_uri_norange @_, \@head, $read_size, $sendfile, $entry;
					return;
				}
			}

			if($do_dir){
				Log::OK::TRACE and log_trace "Static: Listing dir $p";
				#dir listing
				$list_dir->(@_, $p);
				return;
			}
			else {
				Log::OK::TRACE and log_trace "Static: NO DIR LISTING";
				#no valid index found so 404
				rex_error_not_found @_;
				return;
			}
		}




		#File serving
		#
		#=============



		my $entry=$cache->{$path}//$static->open_cache($path,$open_modes, $pre_encoded);
		if($entry){
			if($rex->[uSAC::HTTP::Rex::headers_]{RANGE}){
				send_file_uri_range @_, $entry;
				return;
			}
			else{
				send_file_uri_norange @_, \@head, $read_size, $sendfile, $entry, $no_encoding and $path =~ /$no_encoding/;
				return;
			}
		}
		else {
			if($next){
				return &$next;
			}
			else {
				#no file found so 404
				&rex_error_not_found;
				return;
			}
		}
	}
}




sub send_file {
		my $rex=$_[1];
		#test for ranges
		if($rex->[uSAC::HTTP::Rex::headers_]{RANGE}){
			#send_file_uri_range @_;
			return;
		}
		elsif($_[2]=~m|/$|){
			#list_dir @_;
			return;
		}
		else{
			#Send normal
			#send_file_uri_norange @_;
			return;
		}
	}

	#enable_cache;

1;
