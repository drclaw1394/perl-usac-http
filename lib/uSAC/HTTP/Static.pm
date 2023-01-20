package uSAC::HTTP::Static;
use strict;
use warnings;

use feature qw<say  refaliasing state current_sub>;
no warnings "experimental";
use Carp;
use Log::ger;
use Log::OK;
use JSON;
#no feature "indirect";
use Devel::Peek qw<SvREFCNT>;
#use Scalar::Util qw<weaken>;
#use Errno qw<:POSIX EACCES ENOENT>;
use Fcntl qw(O_NONBLOCK O_RDONLY);
#use File::Spec;
use File::Basename qw<basename dirname>;
use Time::Piece;
use Cwd;
use AnyEvent;
#use Sys::Sendfile;
use IO::FD;

#use uSAC::HTTP ":constants";
use uSAC::HTTP::Code qw<:constants>;
use uSAC::HTTP::Header qw<:constants>;
use uSAC::HTTP::Rex;
use uSAC::HTTP::Constants;


use Errno qw<EAGAIN EINTR EBUSY>;
use Exporter 'import';
our @EXPORT_OK =qw<send_file send_file_uri send_file_uri_aio send_file_uri_sys send_file_uri_aio2 usac_file_under list_dir>;
our @EXPORT=@EXPORT_OK;

#my $path_ext=	qr{\.([^.]*)$}ao;

use constant  READ_SIZE=>4096;

#my %stat_cache;

use enum qw<fh_ content_type_header_ size_ mt_ last_modified_header_ content_encoding_ cached_>;
use constant KEY_OFFSET=>0;

use enum ("mime_=".KEY_OFFSET, qw<default_mime_ html_root_ cache_ cache_size_ cache_sweep_size_ cache_timer_ cache_sweep_interval_ end_>);
use constant KET_COUNT=>end_-mime_+1;
use constant RECURSION_LIMIT=>10;
use IO::FD;

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
	$self->[cache_sweep_interval_]=$options{cache_sweep_interval}//120;
	$self->[cache_size_]=$options{cache_size};
	bless $self, $package;
  $self->enable_cache;
  #$self->disable_cache;
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
						(0<=$start) and
						($start<$size) and
						(0<=$end) and
						($end<$size) and
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
		$self->[cache_timer_]=AE::timer 0, $self->[cache_sweep_interval_], sub {
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

use constant OPEN_MODE=>O_RDONLY|O_NONBLOCK;

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

		#lookup mime type
		#
		my $ext=substr $abs_path, rindex($abs_path, ".")+1;
		#next if $ext==$pre;

		my @entry;
		$entry[content_type_header_]=[HTTP_CONTENT_TYPE, ($self->[mime_]{$ext}//$self->[default_mime_])];
		#say stat _;
		$entry[size_]=(stat _)[7];
		$entry[mt_]=(stat _)[9];
		if($pre){
			$entry[content_encoding_]=[HTTP_CONTENT_ENCODING, $encoding_map{$pre}];
		}
		else{
			$entry[content_encoding_]=[];
		}
    
    if(defined IO::FD::sysopen $in_fh,$path,OPEN_MODE|($mode//0)){
      #say $in_fh;
      #open $in_fh,"<:mmap", $path or return;
      $entry[fh_]=$in_fh;
      Log::OK::DEBUG and log_debug "Static: preencoded com: ".$pre;
      Log::OK::TRACE and log_trace "content encoding: ". join ", ", $entry[content_encoding_]->@*;
      my $tp=gmtime($entry[mt_]);
      $entry[last_modified_header_]=[HTTP_LAST_MODIFIED, $tp->strftime("%a, %d %b %Y %T GMT")];
      # Cache the entry only if cache is enabled
      $entry[cached_]=1 and $self->[cache_]{$abs_path}=\@entry if $self->[cache_timer_];
      return \@entry;
    }
    else {
      Log::OK::ERROR and log_error " Error opening file $abs_path: $!";
    }
	}
  #Log::OK::WARN and log_warn "Could not open file $abs_path";
  undef;
}


#process without considering ranges
#This is useful for constantly chaning files and remove overhead of rendering byte range headers
sub send_file_uri_norange {
  #return a sub with cache an sysroot aliased
  #use  integer;

  my ($matcher, $rex, $code, $out_headers, $reply, $cb, $next, $read_size, $sendfile, $entry, $no_encoding)=@_;

  Log::OK::TRACE and log_trace("send file no range");

  $rex->[uSAC::HTTP::Rex::in_progress_]=1;
  my $in_fh=$entry->[fh_];

  my ($content_length, $mod_time)=($entry->[size_],$entry->[mt_]);

  $reply="";
  #process caching headers
  my $headers=$_[REX][uSAC::HTTP::Rex::headers_];#$rex->headers;
  #my $code=HTTP_OK;
  my $etag="\"$mod_time-$content_length\"";

  my $offset=0;	#Current offset in file
  my $total=0;	#Current total read from file
  my $rc;

  my @ranges;


  #Ignore caching headers if we are processing as an error
  my $as_error= HTTP_BAD_REQUEST<=$code;
  if(!$as_error){
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
  }

  #Add no compress (ie identity) if encoding is not set
  #and if no_encodingflag is set
  #


  unshift($out_headers->@*,
    HTTP_VARY, "Accept",
    $entry->[last_modified_header_]->@*,
    $entry->[content_type_header_]->@*,
    (!$entry->[content_encoding_]->@* and $no_encoding)
    ? (HTTP_CONTENT_ENCODING, "identity")
    : $entry->[content_encoding_]->@*,


    HTTP_ETAG, $etag,
    HTTP_ACCEPT_RANGES,"bytes"
  )
  ;

  if(!$as_error and $headers->{RANGE}){
    Log::OK::DEBUG and log_debug "----RANGE REQUEST IS: $headers->{RANGE}";
    @ranges=_check_ranges $rex, $content_length;
    unless(@ranges){
      $code=HTTP_RANGE_NOT_SATISFIABLE;
      push @$out_headers, HTTP_CONTENT_RANGE, "bytes */$content_length";
      $next->( $matcher,$rex,$code,$out_headers,"");
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


  $next->($matcher, $rex, $code, $out_headers, "" ) and return
  if($rex->[uSAC::HTTP::Rex::method_] eq "HEAD" 
      or $code==HTTP_NOT_MODIFIED);

  # Send file
  # We only use send file if content length is larger than $sendfile
  # and if $sendfile was non zero
  #
  if(($sendfile<=$content_length) && $sendfile){
    no warnings "uninitialized";
    my $do_sendfile;
    my $ww;
    my $session=$rex->[uSAC::HTTP::Rex::session_];
    my $out_fh=$session->fh;

    $do_sendfile=sub {
      Log::OK::TRACE  and log_trace "Doing send file";
      $total+=$rc=IO::FD::sendfile($out_fh, $in_fh, $read_size, $offset);
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
        $rex->[uSAC::HTTP::Rex::dropper_]->(1);
        $do_sendfile=undef;
        $out_fh=undef;
        $ww=undef;
        return;
      }

      elsif($rc){
        $ww=AE::io $out_fh, 1, __SUB__ unless $ww;
        #return;
      }
      elsif( $! != EAGAIN and  $! != EINTR and $! != EBUSY){
        #log_error "Send file error $!";
        $ww=undef;
        $rex->[uSAC::HTTP::Rex::dropper_]->(1);
        $do_sendfile=undef;
        #return;
      }

      else {  
        Log::OK::TRACE and log_trace "Static file read: EAGAIN";
      }

    };

    Log::OK::TRACE  and log_trace "Writing sendfile header";
    #return $next->($matcher, $rex, $code, $out_headers, "", $do_sendfile);

    # Use a 0 for the callback to indicate we don't want one
    # and not to execute the default
    $next->($matcher, $rex, $code, $out_headers, "", $do_sendfile);
    #return $do_sendfile->();
  }

  else{
    #
    # the normal copy and write
    #
    
    #Clamp the readsize to the file size if its smaller
    $read_size=$content_length if $content_length < $read_size;

    my $t;
    my $count=0;
    (sub {
        $count++;
        #This is the callback for itself
        #if no arguments an error occured
        unless(@_){
          #undef $sub;
          $rex->[uSAC::HTTP::Rex::dropper_]->(1);
          undef $rex;
          return;
        }

        my $sub=__SUB__;


        #NON Send file
        #
        #IO::FD::sysseek $in_fh, $offset, 0;
        my $sz=($content_length-$total);
        $sz=$read_size if $sz>$read_size;
        $reply=IO::FD::SV $sz; #reset//allocate buffer
        #$total+=$rc=IO::FD::sysread $in_fh, $reply, $sz;#, $offset;
        $total+=$rc=IO::FD::pread $in_fh, $reply, $sz, $offset;
        $offset+=$rc;

        #non zero read length.. do the write

        #When we have read the required amount of data
        if($total==$content_length){
          if(@ranges){
            return $next->( $matcher, $rex, $code, $out_headers, $reply, sub {
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
              })
          }
          else{
            IO::FD::close $in_fh unless $entry->[cached_];
            return $next->($matcher, $rex, $code, $out_headers, $reply, undef);
          }
        }

        #Data read by more to do
        $rc and	($rex
          ?return $next->($matcher, $rex, $code, $out_headers, $reply, __SUB__)
          :return undef $sub);

        #if ($rc);

        #No data but error
        if( !defined($rc) and $! != EAGAIN and  $! != EINTR){
          log_error "Static files: READ ERROR from file";
          log_error "Error: $!";
          IO::FD::close $in_fh;
          $rex->[uSAC::HTTP::Rex::dropper_]->(1);
          undef $sub;
        }
      })->(undef); #call with an argument to prevent error
  }
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
		my ($line, $rex, $code, $headers, $uri, $next)=@_;
		my $session=$rex->[uSAC::HTTP::Rex::session_];

		my $abs_path=$html_root.$uri;
		stat $abs_path;
    Log::OK::TRACE and "DIR LISTING for $abs_path";
		unless(-d _ and  -r _){

      Log::OK::TRACE and "No dir here $abs_path";
      #rex_error_not_found $line, $rex;
      $_[CODE]=HTTP_NOT_FOUND;
      $_[PAYLOAD]="";
			return &$next;
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
        my $isDir= -d;
        s|^$html_root/||;                       #strip out html_root
        my $base=(split "/")[-1].($isDir? "/":"");

        ["$rex->[uSAC::HTTP::Rex::uri_raw_]$base", $base, stat _]
      }
      @fs_paths;
		my $ren=$renderer//&_html_dir_list;

		my $data="";#"lkjasdlfkjasldkfjaslkdjflasdjflaksdjf";
		$ren->($data, $labels, \@results);	#Render to output
		if($rex->[uSAC::HTTP::Rex::method_] eq "HEAD"){
			$next->($line, $rex, HTTP_OK,[HTTP_CONTENT_LENGTH, length $data, @type] , "",my $cb=undef);

		}
		else{
			$next->($line, $rex, HTTP_OK,[HTTP_CONTENT_LENGTH, length $data, @type] , $data, my $cb=undef);
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
  my $read_size=$options{read_size}//READ_SIZE;
  my $sendfile=$options{sendfile}//0;
  my $open_modes=$options{open_flags}//0;
  my $filter=$options{filter};
  my $no_encoding=$options{no_encoding}//"";
  my $do_dir=$options{list_dir}//$options{do_dir};
  my $pre_encoded=$options{pre_encoded}//[];
  \my @indexes=$options{indexes}//[];
  #TODO: Need to check only supported encodings are provided.

  Log::OK::DEBUG and log_debug "Static files from: $html_root";
  Log::OK::DEBUG and log_debug "DIR Listing: ".($do_dir?"yes":"no");
  Log::OK::DEBUG and log_debug "DIR index: ".(@indexes?join(", ", @indexes):"no");
  Log::OK::DEBUG and log_debug "Filename Filter: ".($filter?$filter: "**NONE**");
  Log::OK::DEBUG and log_debug "Readsize: $read_size";
  Log::OK::DEBUG and log_debug "No encoding filter: ".($no_encoding?$no_encoding:"**NONE**");

  local $"=", ";
  Log::OK::DEBUG and log_debug "Preencoding filter: ".(@$pre_encoded?(@$pre_encoded):"**NONE**");
  Log::OK::DEBUG and log_debug "Sendfile: ".($sendfile?"yes $sendfile":"no");

  Log::OK::TRACE and log_trace "OPTIONS IN: ".join(", ", %options);
  my $static=uSAC::HTTP::Static->new(html_root=>$html_root, %options);

  my $cache=$static->[cache_];
  $html_root=$static->[html_root_];
  my $list_dir=$static->make_list_dir(%options);

  croak "Can not access dir $html_root to serve static files" unless -d $html_root;
  #check for mime type in parent 
  my $inner=sub {
    #create the sub to use the static files here
    my $next=shift;
    my $p;	#tmp variable
    sub {
      # Stack reset
      return &$next unless($_[CODE]);

    

      if($_[HEADER]){

      
        #
        # Previous middleware did not find anything, or we don't have a
        # response just yet
        #
        return &$next unless($_[CODE]<0 or $_[CODE]==HTTP_NOT_FOUND);
       
        
        $p=$_[REX][uSAC::HTTP::Rex::uri_stripped_];

        my $path=$html_root.$p;

        #
        # First this is to report not found  and call next middleware
        # if the filter doesn't match (if a filter exists)
        #
        if($filter and $path !~ /$filter/o){
          $_[PAYLOAD]="";
          $_[CODE]=HTTP_NOT_FOUND;
          push $_[HEADER]->@*, HTTP_CONTENT_LENGTH, 0;
          return &$next;
        }

        #Push any user static headers
        push $_[HEADER]->@*, @$headers;

        Log::OK::TRACE and log_trace "static: html_root: $html_root";





        # File serving
        #
        # Attempts to open the file and send it. If it fails, the next static middleware is called if present

        my $pre_encoded_ok=($pre_encoded and $path=~/gz$/ or $_[1]->headers->{ACCEPT_ENCODING}//"" !~ /gzip/)
        ?$pre_encoded
        :[];


        my $entry=$cache->{$path}//$static->open_cache($path,$open_modes, $pre_encoded_ok);


        if($entry){
          send_file_uri_norange(@_, $next, $read_size, $sendfile, $entry, ($no_encoding and $path =~ /$no_encoding/));

        }
        elsif($do_dir || @indexes and substr($path, -1) eq "/") {
          #Server dir listing if option is specified
          #
          #=========================================
          #attempt to do automatic index file.
          my $entry;
          for(@indexes){
            my $path=$html_root.$p.$_;
            Log::OK::TRACE and log_trace "Static: Index searching PATH: $path";
            $entry=$cache->{$path}//$static->open_cache($path);
            next unless $entry;
            $_[HEADER]=[];
            send_file_uri_norange(@_, $next, $read_size, $sendfile, $entry);
            return 1;
          }

          if($do_dir){
            Log::OK::TRACE and log_trace "Static: Listing dir $p";
            #dir listing
            $_[PAYLOAD]=$p;   # hack
            $_[CB]=$next;     # hack
            &$list_dir;
          }
          else {
            Log::OK::TRACE and log_trace "Static: NO DIR LISTING";
            $_[PAYLOAD]="";
            $_[CODE]=HTTP_NOT_FOUND;
            push $_[HEADER]->@*, HTTP_CONTENT_LENGTH, 0;
            &$next;
            #no valid index found so 404
            #&rex_error_not_found;# @_;
            #return 1;
          }
        }
        else{
          # We did not locate the file. Set a not found error and forward to
          # the next middleware
          $_[PAYLOAD]="";
          $_[CODE]=HTTP_NOT_FOUND;
          push $_[HEADER]->@*, HTTP_CONTENT_LENGTH, 0;
          &$next;
        }
      }
      else {
        #Not HEADER
        &$next;
      }
    }
  };

  my $outer=sub {
    my $next=shift;
  };

  [$inner, $outer];
}
*static_under=\*usac_file_under;

1;
