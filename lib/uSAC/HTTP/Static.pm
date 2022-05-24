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
use Scalar::Util qw<weaken>;
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

my $read_size=4096;;
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
		$self->[cache_timer_]=AE::timer 0, 10,sub {
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
			Log::OK::DEBUG and log_debug "Static: preencoded com: ".$pre;
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
		Log::OK::TRACE and log_trace("send file no range");
		my $session=$rex->[uSAC::HTTP::Rex::session_];

		weaken $session;
		weaken $rex;
		#weaken $matcher;

		$session->[uSAC::HTTP::Session::in_progress_]=1;

		my $in_fh=$entry->[fh_];

		my ($content_length, $mod_time)=($entry->[size_],$entry->[mt_]);

		my $reply="";
		#process caching headers
		my $headers=$_[1][uSAC::HTTP::Rex::headers_];#$rex->headers;
		my $code=HTTP_OK;
		my $etag="\"$mod_time-$content_length\"";

		my $offset=0;	#Current offset in file
		my $total=0;	#Current total read from file
		my $rc;

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
					#Do dropper as we reached the end. use keep alive 
					$session->[uSAC::HTTP::Session::dropper_]->(1);
					$out_fh=undef;
					$ww=undef;
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
					log_error "Send file error";
					log_error $!;
					#delete $cache{$abs_path};
					#close $in_fh;
					$session->[uSAC::HTTP::Session::dropper_]->();
					return;
				}

				else {  
					Log::OK::TRACE and log_trace "Static file read: EAGAIN";
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

			#HTTP_CONTENT_LENGTH, $content_length,			#need to be length of multipart

			HTTP_ETAG,$etag,
			HTTP_ACCEPT_RANGES,"bytes",
			@$user_headers


		];

		if($headers->{RANGE}){
			Log::OK::DEBUG and log_debug "----RANGE REQUEST IS: $headers->{RANGE}";
			@ranges=_check_ranges $rex, $content_length;
			unless(@ranges){
				$code=HTTP_RANGE_NOT_SATISFIABLE;
				push @$out_headers, HTTP_CONTENT_RANGE, "bytes */$content_length";

				rex_write $matcher,$rex,$code,$out_headers,"";
				return;
			}
			elsif(@ranges==1){
				$code=HTTP_PARTIAL_CONTENT;
				my $total_length=0;
				$total_length+=($_->[1]-$_->[0]+1) for @ranges;
				push @$out_headers,
				HTTP_CONTENT_RANGE, "bytes $ranges[0][0]-$ranges[0][1]/$content_length",
				HTTP_CONTENT_LENGTH, $total_length;

				$content_length=$total_length;
				$offset= $ranges[0][0];
				shift @ranges;
			}
			else{

			}
		}
		else {
				push @$out_headers, HTTP_CONTENT_LENGTH, $content_length;

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

		my $recursion_limit=10;
		my $t;
		my $count=0;
                (sub {
			$count++;
			#This is the callback for itself
			#if no arguments an error occured
			unless(@_){
				#undef $sub;
				$session->[uSAC::HTTP::Session::dropper_]->();
				#undef $rex;
				return;
			}
			my $sub=__SUB__;

			state $recursion_counter;
			$recursion_counter++;

			$reply=""; #reset buffer
                        #NON Send file
                        seek $in_fh, $offset, 0;
                        $total+=$rc=sysread $in_fh, $reply, $read_size;#, $offset;
			$offset+=$rc;

                        #non zero read length.. do the write
                        if($total==$content_length){    #end of file
				Log::OK::DEBUG and log_debug "Static: Complete file/range read";
				undef $t;
				if(@ranges){
                                        rex_write $matcher, $rex, $code, $out_headers, $reply, sub {
                                                unless(@_){
                                                        return $sub->();
                                                }

                                                #TODO: FIX MULTIPART RANGE RESPONSE
                                                my $r=shift @ranges;
                                                $offset=$r->[0];
                                                $total=0;
                                                $content_length=$r->[1];

                                                #write new multipart header
                                                return $sub->(undef);           #Call with arg
                                        };

					return

				} else {

					#write and done
					Log::OK::DEBUG and log_debug "Static: write and done: writer sub ref count: ".SvREFCNT($sub);
					rex_write $matcher, $rex, $code, $out_headers, $reply, undef;
					return;
				}
                        }

                        elsif($rc){
				#TODO: need to force break deep recursion due to fast fat pipes
				# Possibly defer the callback every 10 or 100 times to break the chain
				#
				
				if($recursion_counter>=$recursion_limit){
					$recursion_counter=0;
					#Do asynchronous callback in next event iteration
					#my $sub=__SUB__;
					#weaken $sub;
					$t=AE::timer 0, 0, sub {
						$t=undef;
						if($rex){
							#Log::OK::DEBUG and log_debug "parital async write of $rc bytes $total/$content_length bytes on rex $rex->[uSAC::HTTP::Rex::id_]";
							#Log::OK::DEBUG and log_debug "Static: timeout: writer sub ref count: ".SvREFCNT($sub);
							rex_write $matcher, $rex, $code, $out_headers, $reply, $sub;
						}
						else {
							undef $sub;
						}
					};

				}
				else {
					#Do synchronous callback
					if($rex){
						#Log::OK::DEBUG and log_debug "parital write of $rc bytes $total/$content_length bytes on rex $rex->[uSAC::HTTP::Rex::id_]";
						#Log::OK::DEBUG and log_debug "$sub";
						#Log::OK::DEBUG and log_debug "Static: writer sub ref count: ".SvREFCNT($sub);
						rex_write $matcher, $rex, $code, $out_headers, $reply, __SUB__;
					}
					else {
						#If the rex is undef, it was closed by the server sweeping inactive sessions.
						undef $sub;
					}
				}
                                return;
                        }
                        elsif( !defined($rc) and $! != EAGAIN and  $! != EINTR){
                                log_error "Static files: READ ERROR from file";
                                log_error "Error: $!";
                                #delete $cache{$abs_path};
                                close $in_fh;
				#error was with input file not socket. So keep socket alive	
                                $session->[uSAC::HTTP::Session::dropper_]->(1);
				undef $sub;
				#undef $rex;
                                return;
                        }
			else {
                                log_error "Static files: Range beyond EOF";
				log_error "REX: ".$rex->uri;
				log_error "REX: ".Dumper $rex->headers;
				log_error "REX: total length: $total";;

				#End of file reached but content range not satisfied
				#DropClose connection
                                $session->[uSAC::HTTP::Session::dropper_]->();
				undef $sub;
				#undef $rex;
                                return;
			}

                        #else {  EAGAIN }

        })->(undef); #call with an argument to prevent error

	#weaken $sub;	#NOTE: This is very important! Memory leak otherwise


}



sub _html_dir_list {
	sub {
		my $headers=$_[1];
		my $entries=$_[2];
		#TODO: add basic style to improve the look?
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
		if($rex->[uSAC::HTTP::Rex::method_] eq "HEAD"){
			rex_write $line, $rex, HTTP_OK,[HTTP_CONTENT_LENGTH, length $data, @type] , "";

		}
		else{
			rex_write $line, $rex, HTTP_OK,[HTTP_CONTENT_LENGTH, length $data, @type] , $data;
		}
	}
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
	Log::OK::INFO and log_info "Serving file from  $html_root";
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
				send_file_uri_norange @_, \@head, $read_size, $sendfile, $entry;
				return 1;
			}

			if($do_dir){
				Log::OK::TRACE and log_trace "Static: Listing dir $p";
				#dir listing
				$list_dir->(@_, $p);
				return 1;
			}
			else {
				Log::OK::TRACE and log_trace "Static: NO DIR LISTING";
				#no valid index found so 404
				rex_error_not_found @_;
				return 1;
			}
		}




		# File serving
		#
		# Attempts to open the file and send it. If it fails, the next static middleware is called if present
		

		my $entry=$cache->{$path}//$static->open_cache($path,$open_modes, $pre_encoded);
		if($entry){
			Log::OK::DEBUG and log_debug "Serving static file: $path on rex: $_[1][uSAC::HTTP::Rex::id_]";
			send_file_uri_norange @_, \@head, $read_size, $sendfile, $entry, $no_encoding and $path =~ /$no_encoding/;
			return 1;
		}
		else {
			if($next){
				return &$next;
			}
			else {
				#no file found so 404
				&rex_error_not_found;
				return 1;
			}
		}
	}
}

1;




