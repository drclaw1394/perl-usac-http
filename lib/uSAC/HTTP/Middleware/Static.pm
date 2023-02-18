package uSAC::HTTP::Middleware::Static;
use strict;
use warnings;


use feature qw<say  refaliasing state current_sub>;
no warnings "experimental";
use uSAC::HTTP::FileMetaCache;
use Carp;
use Log::ger;
use Log::OK;
use JSON;
use File::Basename qw<basename dirname>;
use AnyEvent;
use IO::FD;

#use uSAC::HTTP ":constants";
use uSAC::HTTP::Code qw<:constants>;
use uSAC::HTTP::Header qw<:constants>;
use uSAC::HTTP::Rex;
use uSAC::HTTP::Constants;


use Errno qw<EAGAIN EINTR EBUSY>;
use Exporter 'import';
our @EXPORT_OK =qw<usac_file_under usac_static_under>;
our @EXPORT=@EXPORT_OK;

#my $path_ext=	qr{\.([^.]*)$}ao;

use constant  READ_SIZE=>4096;

#my %stat_cache;

use enum qw<fh_ content_type_header_ size_ mt_ last_modified_header_ content_encoding_ cached_ key_ etag_ source_ user_>;
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
	$self->[cache_sweep_interval_]=$options{cache_sweep_interval}//30;
	$self->[cache_size_]=$options{cache_size};
	bless $self, $package;
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



#process without considering ranges
#This is useful for constantly chaning files and remove overhead of rendering byte range headers
sub send_file_uri_norange {
  #return a sub with cache an sysroot aliased
  #use  integer;

  my ($matcher, $rex, $code, $out_headers, $reply, $cb, $next, $read_size, $sendfile, $entry, $closer)=@_;

  Log::OK::TRACE and log_trace("send file no range");


  $rex->[uSAC::HTTP::Rex::in_progress_]=1;
  my $in_fh=$entry->[fh_];

  my ($content_length, $mod_time)=($entry->[size_],$entry->[mt_]);

  $reply="";
  #process caching headers
  my $headers=$_[REX][uSAC::HTTP::Rex::headers_];#$rex->headers;
  #my $code=HTTP_OK;
  # my $etag="\"$mod_time-$content_length\"";

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
      $code=HTTP_OK and last if  $entry->[etag_] !~ /$t/;
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

  push @$out_headers, 
    $entry->[user_]->@*, 
    HTTP_VARY, "Accept",
    HTTP_ACCEPT_RANGES,"bytes";

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
        #$reply=IO::FD::SV $sz; #reset//allocate buffer
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

            $closer->($entry);
            #IO::FD::close $in_fh unless $entry->[cached_];
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
          #IO::FD::close $in_fh;
          $closer->($entry);
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
  #\my %cache=$self->[cache_];
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
      $_[CB]=undef;
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

  my $mime=$options{mime}=$parent->resolve_mime_lookup;
  my $default_mime=$options{default_mime}=$parent->resolve_mime_default;

  my $headers=$options{headers}//[];
  my $read_size=$options{read_size}//READ_SIZE;
  my $sendfile=$options{sendfile}//0;
  my $open_modes=$options{open_flags}//0;
  my $filter=$options{filter};
  my $no_encoding=$options{no_encoding}//"";
  my $do_dir=$options{list_dir}//$options{do_dir};
  my $pre_encoded=$options{pre_encoded}//{};

  \my @indexes=$options{indexes}//[];


  my @suffix_indexes;
  # Combinations of all pre encoded options. The unencoded form is last
  #
  @suffix_indexes=
  map {
    my $index=$_; 
    (map {
      $index.$_
    } keys %$pre_encoded);
  } @indexes;


  # Add unencoded options at end of list
  #
  push @suffix_indexes, @indexes;


  # Setup the prencoded  array to iterate through for 'normal' files
  # Add the empty suffix to allow matching of unencoded content.
  # Assumes file names are in the form of index.html.gz
  #
  my @pre_encoded= ((map {".$_"} keys(%$pre_encoded)), "");




  #TODO: Need to check only supported encodings are provided.

  Log::OK::DEBUG and log_debug "Static files from: $html_root";
  Log::OK::DEBUG and log_debug "DIR Listing: ".($do_dir?"yes":"no");
  Log::OK::DEBUG and log_debug "DIR index: ".(@indexes?join(", ", @indexes):"no");
  Log::OK::DEBUG and log_debug "Filename Filter: ".($filter?$filter: "**NONE**");
  Log::OK::DEBUG and log_debug "Readsize: $read_size";
  Log::OK::DEBUG and log_debug "No encoding filter: ".($no_encoding?$no_encoding:"**NONE**");

  local $"=", ";
  Log::OK::DEBUG and log_debug "Preencoding filter: ".(%$pre_encoded?(%$pre_encoded):"**NONE**");
  Log::OK::DEBUG and log_debug "Sendfile: ".($sendfile?"yes $sendfile":"no");

  Log::OK::TRACE and log_trace "OPTIONS IN: ".join(", ", %options);
  my $static=uSAC::HTTP::Middleware::Static->new(html_root=>$html_root, %options);
  my $fmc=uSAC::HTTP::FileMetaCache->new(mime_table=>$options{mime}, default_mime=>$options{default_mime});

  my $opener=$fmc->opener;
  my $closer=$fmc->closer;
  state $timer=AE::timer 0, 10, $fmc->sweeper;
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





        # File and Directory serving 
        #
        # Attempts to open the file and send it. If it fails, the next static
        # middleware is called if present

        
        my $entry;
        #my $path=$html_root.$p;
        my $enc="";
        my $content_type;

        if(substr($path, -1) eq "/") {
          # Attempt to match a file within a directory to that in the index list
          # Update content type to the located file
          #
          if(@suffix_indexes ){

            Log::OK::TRACE and log_trace "Static: Index searching PATH: $path";
            for(@suffix_indexes){
              my $_path=$path.$_;
              $entry=$opener->($_path, $open_modes);#, \@suffix_indexes);
              if($entry){
                my $index=rindex $_path, ".";
                my $ext=substr $_path, $index+1;
                $content_type=$mime->{$ext}//$default_mime;
                last;
              }
              else {
                Log::OK::TRACE and log_trace "Static: did not locate index: $path";
              }
            }
            #goto SEND_FILE if $entry
          }

          #
          if($do_dir and !$entry){
            # Don't want an index file, just a dir listing
            #
            Log::OK::TRACE and log_trace "Static: Listing dir $p";
            #dir listing
            $_[PAYLOAD]=$p;   # hack
            $_[CB]=$next;     # hack
            return &$list_dir;
          }
          elsif(!$entry){
            # Normally dir listing and index is disabled.
            # Return non found
            #
            Log::OK::TRACE and log_trace "Static: NO DIR LISTING";
            $_[PAYLOAD]="";
            $_[CODE]=HTTP_NOT_FOUND;
            push $_[HEADER]->@*, HTTP_CONTENT_LENGTH, 0;
            return &$next;
          }
        }

        else {
          # Attempt a normal file serve
          #
          Log::OK::TRACE and log_trace "Working on opening normal file";
          my $index=rindex $path, ".";
          my $ext=substr $path, $index+1;
          $content_type=$mime->{$ext}//$default_mime;
                

          if($pre_encoded and ($_[REX][uSAC::HTTP::Rex::headers_]{"ACCEPT_ENCODING"}//"")=~/(gzip)/){
            # Attempt to find a pre encoded file when the client asks and if its enabled
            #
            #say  $_[REX][uSAC::HTTP::Rex::headers_]{"ACCEPT_ENCODING"};
            $enc=$1;
            my $enc_ext=$pre_encoded->{$1};
            $entry=$opener->($path.$enc_ext, $open_modes) if $enc_ext;
            unless($entry){
              $entry=$opener->($path, $open_modes);
              $enc=($no_encoding and $ext=~/$no_encoding/)?"identity":"";

            }
          }
          else{
            # No preencoded files enabled
            $entry=$opener->($path, $open_modes);
          }

          unless($entry){
            # We did not locate the file. Set a not found error and forward to
            # the next middleware
            #
            $_[PAYLOAD]="";
            $_[CODE]=HTTP_NOT_FOUND;
            push $_[HEADER]->@*, HTTP_CONTENT_LENGTH, 0;
            return &$next;
          }
        }

        # Setup meta cache fields if they don't exist
        #
        unless($entry->[user_]){
          $entry->[user_]=[
            HTTP_CONTENT_TYPE, $content_type, #($mime->{$ext}//$default_mime),
            HTTP_LAST_MODIFIED, POSIX::strftime("%a, %d %b %Y %T GMT",
              CORE::gmtime($entry->[mt_])),
            HTTP_ETAG, "\"$entry->[mt_]-$entry->[size_]\"",
          ];
        }

        # Finally push the content encoding encountered along the way
        #
        push @{$_[HEADER]}, HTTP_CONTENT_ENCODING, $enc if $enc;

        send_file_uri_norange(@_, $next, $read_size, $sendfile, $entry, $closer);

      }
      else {
        #No HEADER
        &$next;
      }
    }
  };

  my $outer=sub {
    my $next=shift;
  };

  [$inner, $outer];
}
*usac_static_under=\*usac_file_under;

1;
