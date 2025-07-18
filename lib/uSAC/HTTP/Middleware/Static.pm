package uSAC::HTTP::Middleware::Static;
use strict;
use warnings;
use feature qw<refaliasing state current_sub>;
no warnings "experimental";

use uSAC::Log;
use Log::OK;

use uSAC::IO;

use File::Meta::Cache;
use POSIX ();

use IO::FD;
use uSAC::FastPack::Broker;

use Import::These qw<uSAC:: Util ::HTTP:: Code Header Rex Constants Route>;

use Export::These (
  "uhm_static_root",     
  "uhm_static_file", # Preload (cache) a file in memory
  "uhm_static_content", # d
  );

use Errno qw<EAGAIN EINTR EBUSY>;

use constant::more  READ_SIZE=>4096*32;


use Time::Local qw<timelocal_modern>;
my @months = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
my $i=0;
my %months= map {$_,$i++} @months;

my %ctx;

sub send_file_uri {
  #return a sub with cache an sysroot aliased
  #use  integer;

  my ($matcher, $rex, $in_header, $out_headers, $reply, $cb, $next, $read_size, $sendfile, $entry, $closer)=@_;

  Log::OK::TRACE and log_trace("send file no range");


  $rex->[uSAC::HTTP::Rex::in_progress_]=1;
  # my $in_fh=$entry->[File::Meta::Cache::fd_];

  my ($content_length, $mod_time)=($entry->[File::Meta::Cache::stat_][7], $entry->[File::Meta::Cache::stat_][9]);

  $reply="";
  #process caching headers
  my $headers=$_[IN_HEADER];

  my $offset=0;	#Current offset in file
  my $total=0;	#Current total read from file
  my $rc;

  my @ranges;

  # 
  my $as_error= $rex->[AS_ERROR];

  #Ignore caching headers if we are processing as an error
  if(!$as_error){
    #TODO: needs testing
    for my $t ($headers->{"if-none-match"}){
      #HTTP_IF_NONE_MATCH){
      #
      $rex->[STATUS]=HTTP_OK and last unless $t;

      $rex->[STATUS]=HTTP_NOT_MODIFIED and last;
    }

    #TODO: needs testing
    for my $time ($headers->{"if-modified-since"}){
      $rex->[STATUS]=HTTP_OK and last unless $time;

      for($time){
        Log::OK::TRACE and log_trace " converting cookie expires from stamp to epoch";
        my ($wday_key, $mday, $mon_key, $year, $hour, $min, $sec, $tz)=
         /([^,]+), (\d+).([^-]{3}).(\d{4}) (\d+):(\d+):(\d+) (\w+)/;
         #TODO support parsing of other deprecated data formats

        if(70<=$year<=99){
          $year+=1900;
        }
        elsif(0<=$year<=69){
          $year+=2000;
        }
        else{
          #year as is
        }
        #NOTE: timelocal_modern DOES NOT add/subtract time offset. Which is what we want
        #as the time is already gmt
        #
        my $epoch = timelocal_modern($sec, $min, $hour, $mday, $months{$mon_key}, $year);
        $rex->[STATUS]=HTTP_OK and last if $mod_time>$epoch;

      }



      #my $tp=Time::Piece->strptime($time, "%a, %d %b %Y %T GMT");

      $rex->[STATUS]=HTTP_NOT_MODIFIED;
    }
  }

  for my($k, $v)(
    $entry->[File::Meta::Cache::user_]->@*, 
    #HTTP_VARY, "Accept", 
    HTTP_ACCEPT_RANGES, "bytes" #// Even when used as cache, we can repsonde with byte range
  ){
    # NOTE: Only set headers if not already set. 
    # Give caching system a change to do it thing!
    $out_headers->{$k}//=$v;
  }

  if(!$as_error and $headers->{range}){
    Log::OK::DEBUG and log_debug "----RANGE REQUEST IS: $headers->{range}";
    #@ranges=_check_ranges $rex, $content_length;

    # parse ranges here
    my $ifr=$_[IN_HEADER]{"if-range"};

    #check range is present
    #response code is then 206 partial
    #
    #Multiple ranges, we then return multipart doc
    my $unit;
    my $i=0;
    my $pos;	
    my $size=$content_length;
    for($headers->{range}=~tr/ //dr){				#Remove whitespace
      #exract unit
      $pos=index $_, "=";
      $unit= substr $_, 0, $pos++;
      my $specs= substr $_, $pos;
      for my $spec (split(",",$specs)){
        my ($start, $end)=split "-", $spec; #, substr($_, $pos, $pos2-$pos);
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
          push @ranges, [$start, $end];
        }
        else {
          #416 Range Not Satisfiable
          @ranges=();
        }

      }

    }



    unless(@ranges){
      Log::OK::TRACE and log_trace "Range not satisfiable";
      $rex->[STATUS]=HTTP_RANGE_NOT_SATISFIABLE;

      $out_headers->{HTTP_CONTENT_RANGE()}="bytes */$content_length";

      $next->($matcher, $rex, $in_header, $out_headers, "");
      return;
    }
    elsif(@ranges==1){
      Log::OK::TRACE and log_trace "Range Single";
      $rex->[STATUS]=HTTP_PARTIAL_CONTENT();

      my $total_length=0;
      $total_length+=($_->[1]-$_->[0]+1) for @ranges;
      

      for my($k, $v)(
        HTTP_CONTENT_RANGE, "bytes $ranges[0][0]-$ranges[0][1]/$content_length",
        HTTP_CONTENT_LENGTH, $total_length
      ){

        # Allow cache to do its thing but only setting if it doesn't exist
        #
        $out_headers->{$k}//=$v;

      }

      $content_length=$total_length;
      $offset= $ranges[0][0];
      Log::OK::TRACE and log_trace "Content length for single range: $content_length, offset $offset";
      shift @ranges;
    }
    else{
      $_[OUT_HEADER]{HTTP_CONTENT_TYPE()}="multipart/byteranges";
      Log::OK::TRACE and log_trace "Range multiple .. not implemented";

    }
  }
  else {
    # process as error or non partial content
    # Allow for caching
    $out_headers->{HTTP_CONTENT_LENGTH()}//= $content_length;
  }


  if(($rex->[METHOD] eq "HEAD" or $rex->[STATUS]==HTTP_NOT_MODIFIED)){
    Log::OK::TRACE and log_trace "Range was head request";
    #$closer->(delete $ctx{$rex});
    my $t=delete $ctx{$rex};
    $closer->($t->[0]);
    $next->($matcher, $rex, $in_header, $out_headers, "" );
    return;
  }


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
      $total+=$rc=IO::FD::sendfile($out_fh, $entry->[File::Meta::Cache::fd_], $read_size, $offset);

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
        #$rex->[uSAC::HTTP::Rex::dropper_]->(1);
        $rex->[uSAC::HTTP::Rex::session_]->error();;
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
        $ww=undef;
        #$rex->[uSAC::HTTP::Rex::dropper_]->(1);
        $rex->[uSAC::HTTP::Rex::session_]->error();;
        $do_sendfile=undef;
        #return;
      }

      else {  
        Log::OK::TRACE and log_trace "Static file read: EAGAIN";
      }

    };

    Log::OK::TRACE  and log_trace "Writing sendfile header";

    # Use a 0 for the callback to indicate we don't want one
    # and not to execute the default
    $next->($matcher, $rex, $in_header, $out_headers, "", $do_sendfile);
  }

  else{
    #
    # the normal copy and write
    #
    Log::OK::TRACE and log_trace  'Normal file read/copy/write';

    #Clamp the readsize to the file size if its smaller
    #$read_size=$content_length if $content_length < $read_size;

    my $t;
    my $count=0;
    my $sub;
    $sub=sub {
      #Log::OK::TRACE and log_trace "--- MAIN STATIC CALLBACK for $rex from ".caller;
      $count++;
      #This is the callback for itself
      #if no arguments an error occured
      unless(@_){
        Log::OK::TRACE and log_trace __PACKAGE__." Handing error in normal file read/copy/write for $rex";
        my $t=delete $ctx{$rex};
        $closer->($t->[0]);
        @$t=();
        return;
      }



      #NON Send file
      #
      my $sz=($content_length-$total);
      $sz=$read_size;# if $sz>$read_size;
      #Log::OK::TRACE and log_trace "Total size: $total, content length: $content_length  difference: @{[$content_length-$total]}, size $sz  offset $offset,  fh $in_fh";
      $total+=$rc=IO::FD::pread $entry->[File::Meta::Cache::fd_], $reply, $sz, $offset;
      #Log::OK::TRACE and log_trace "Size of read is $sz,  offset id $offset rc is $rc  for rex $rex";
      $offset+=$rc;

      #Log::OK::TRACE and log_trace "Total size: $total, content length: $content_length  difference: @{[$content_length-$total]}, size $sz  offset $offset,  fh $in_fh";
      #non zero read length.. do the write

      #When we have read the required amount of data
      if($total==$content_length){
        Log::OK::TRACE and log_trace "Full file content read";
        if(@ranges){
          Log::OK::TRACE and log_trace "Ranges to send still";
          return $next->( $matcher, $rex, $in_header, $out_headers, $reply, sub {
              unless(@_){
                return __SUB__->();
              }

              #TODO: FIX MULTIPART RANGE RESPONSE
              my $r=shift @ranges;
              $offset=$r->[0];
              $total=0;
              $content_length=$r->[1];

              #write new multipart header
              __SUB__->(undef);
              return;
            })
        }
        else{
          Log::OK::TRACE and log_trace "No more ranges to send";
          Log::OK::TRACE and log_trace __PACKAGE__."------REMOVING CONTEXT before sending file $rex";
          my $t=delete $ctx{$rex};
          $closer->($t->[0]);
          #$t->[1]=undef;
          @$t=();
          $next->($matcher, $rex, $in_header, $out_headers, $reply, undef);
          return;
        }
      }

      #Log::OK::TRACE and log_trace "File content still remains to be sent";

      #Data read but more to do
      if($rc){
        #Log::OK::TRACE and log_trace "We have a and RC $rc";
        if ($rex){

          $next->($matcher, $rex, $in_header, $out_headers, $reply, __SUB__);
          return;
        }
        else {
          log_error " NO REX in ....";
          return;
        }
      }
      else{
        Log::OK::TRACE and log_trace "DO NOT HAVE RC $rc";
      }


      #if ($rc);
      #No data but error
      if( !defined($rc) and $! != EAGAIN and  $! != EINTR){
        log_error "Static files: READ ERROR from file";
        log_error "Error: $!";
        Log::OK::ERROR and log_error Dumper $entry;
        $rex->[uSAC::HTTP::Rex::session_]->error();;
      }
    };
    $ctx{$rex}[1]=$sub; ## and sub to ctx
    $sub->(undef); #call with an argument to prevent error
  }
}



sub _html_dir_list {
	sub {
		my $headers=$_[1];
		my $entries=$_[2];
		#TODO: add basic style to improve the look?
		if($headers){
      $_[0].='<!DOCTYPE html>
      <html>
      <body>
      ';
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
		$_[0].="</table>
    </body>

    </html>";
	}
}

sub _json_dir_list {
  require JSON;
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
		$_[0].=JSON::encode_json( \@tuples);
	}

}

sub _make_list_dir {

  my %options=@_;
  #\my $html_root=\$options{html_root};
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
		$renderer=!defined $renderer? &_html_dir_list : $renderer;
		@type=(HTTP_CONTENT_TYPE, "text/html");
	}
	
	sub{
		my ($line, $rex, $in_header, $headers, undef, $next, $html_root, $uri)=@_;
		my $session=$rex->[uSAC::HTTP::Rex::session_];
    
    # Ensure html root has trailing slash
    $html_root.="/" unless $html_root=~m|/$|;

		my $abs_path=$html_root.$uri;
		stat $abs_path;
    Log::OK::TRACE and log_trace "DIR LISTING for $abs_path";
    Log::OK::TRACE and log_trace "HTML ROOT is $html_root";
		unless(-d _ and  -r _){
      Log::OK::TRACE and log_trace "No dir here $abs_path";
      $_[REX][STATUS]=HTTP_NOT_FOUND;

      $_[PAYLOAD]="";
      $_[CB]=undef;
			return &$next;
		}

		#build uri from sysroot
		my @fs_paths;
		if($abs_path eq $html_root){
			@fs_paths=<$abs_path*>;	
		}
		else{
			@fs_paths=<$abs_path.* $abs_path*>;	
		}
		state $labels=[qw<name dev inode mode nlink uid gid rdev size access_time modification_time change_time block_size blocks>];
		my @results
      =map {
        my $isDir= -d;
        s|^$html_root||;                       #strip out html_root
        my $base=(split "/")[-1].($isDir? "/":"");

        #["$_[IN_HEADER]{':path'}$base", $base, stat _]
        ["$_[REX][PATH]$base", $base, stat _]
      }
      @fs_paths;
		my $ren=$renderer//&_html_dir_list;

		my $data="";
		$ren->($data, $labels, \@results);	#Render to output

    # Set status if not already set
    $_[REX][STATUS]=HTTP_OK;

    $_[OUT_HEADER]{HTTP_CONTENT_LENGTH()}=length $data;

    for my ($k,$v)(@type){
      $_[OUT_HEADER]{$k}=$v;
    }
		if($_[REX][METHOD] eq "HEAD"){
			$next->($line, $rex, $in_header, $headers , "", my $cb=undef);

		}
		else{
			$next->($line, $rex, $in_header,$headers , $data, my $cb=undef);
		}
	}
}




#Server static files under the specified root dir
#Dual mode. Also acts as innerware

#Specifies the url prefix (and or regex) to match
#The prefix is removed and

# NOTE: If payload is NOT UNDEF, it is used as the relative path to search for!
#       Otherwise the path to search for is from the url path in the request
sub uhm_static_root {
  
#my $html_root;
  my %options;
  my $frame=[caller];
  if(@_ % 2){
    # Odd number of arguments assume last item is html root
    my $tmp=pop;
    %options=@_;
    unshift $options{roots}->@*, $tmp;
  }
  else {
    # Even or zero arguments
    %options=@_;
  }

  # Resolve paths
  $options{roots}->@* =
    map { m|/$| ? $_ : "$_/"; } # Ensure the dir ends with a slash

    map {uSAC::Util::path $_, $frame} $options{roots}->@*;


  my $headers=$options{headers}//[];
  my $read_size=$options{read_size}//READ_SIZE;
  my $sendfile=$options{sendfile}//0;
  my $open_modes=$options{open_flags}//0;
  my $allow=$options{allow};
  my $block=$options{block};
  my $template=$options{template};
  my $no_encoding=$options{no_encoding}//"";
  my $do_dir=$options{list_dir}//$options{do_dir};
  my $pre_encoded=$options{pre_encoded}//{};
  my $prefix=$options{prefix};
  \my @roots=$options{roots};

  \my @indexes=($options{index}//$options{indexes}//[]);

  # If given a meta cache object, use it.  Otherwise create our own
  # External meta cache give caching control to associated middleware
  #
  #
  my $fmc=$options{meta_cache}//File::Meta::Cache->new(no_fh=>1);

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

  Log::OK::DEBUG and log_debug ("Static files from: ".join ", ", $options{roots}->@*);
  Log::OK::DEBUG and log_debug "DIR Listing: ".($do_dir?"yes":"no");
  Log::OK::DEBUG and log_debug "DIR index: ".(@indexes?join(", ", @indexes):"no");
  Log::OK::DEBUG and log_debug "Filename Allow Filter: ".($allow?$allow:"**NONE**");
  Log::OK::DEBUG and log_debug "Filename block Filter: ".($block?$block:"**NONE**");
  Log::OK::DEBUG and log_debug "Readsize: $read_size";
  Log::OK::DEBUG and log_debug "No encoding filter: ".($no_encoding?$no_encoding:"**NONE**");

  local $"=", ";
  Log::OK::DEBUG and log_debug "Preencoding filter: ".(%$pre_encoded?(%$pre_encoded):"**NONE**");
  Log::OK::DEBUG and log_debug "Sendfile: ".($sendfile?"yes $sendfile":"no");

  Log::OK::TRACE and log_trace "OPTIONS IN: ".join(", ", %options);


  my $opener=$fmc->opener;
  my $closer=$fmc->closer;
  my $sweeper=$fmc->sweeper;
  #$fmc->disable;

  my $timer=uSAC::IO::timer 0, 10, sub { 
    #$sweeper->()
  };

  # Register for gracefull shutdown. No new connections should be accepted

  uSAC::Main::usac_listen("server/shutdown/graceful", sub {
      Log::OK::INFO and log_info 'SERVER GRACEFULL SHUTDOWN IN STATIC';
      uSAC::IO::timer_cancel $timer;
  });
  
  my $list_dir=_make_list_dir(%options);

  for my $html_root ($options{roots}->@*){
    die "Can not access dir $html_root to serve static files" unless -d $html_root;
    $html_root=~s|/$||;   # ensure roots do not end in a slash
  }


  #check for mime type in parent 
  my $inner=sub {
    #create the sub to use the static files here
    my $next=shift;
    my $index=shift;
    my $path_only;
    my %ropts=@_;
    my $site=$ropts{site};
    my $mime=$options{mime}=$site->resolve_mime_lookup;
    my $default_mime=$options{default_mime}=$site->resolve_mime_default;

    my $p;	#tmp variable
    my $as_error;
    sub {
      if($_[OUT_HEADER]){
        $as_error=$_[REX][AS_ERROR];
        # 
        # Path is either given with the rex object or passed in by the payload
        # middleware argument.
        #
        #$p=$_[PAYLOAD]||$_[IN_HEADER]{":path_stripped"};
        $p=$_[PAYLOAD]||$_[REX][PATH];

        #
        # Strip the prefix if its specified
        #
        $prefix//=ref($_[ROUTE][1][ROUTE_PATH]) ? "" : $_[ROUTE][1][ROUTE_PATH];
	#if($prefix ne "/"){
        $p=substr $p, length $prefix if ($prefix and index($p, $prefix)==0);
	  #}
        #$p="/" unless $p; #ensure the path ends in a slash if it is root dir
        my $path;

        ROOTS:
        for my $html_root(@roots){
          #
          # Previous middleware did not find anything, or we don't have a
          # response just yet
          #
          return &$next unless($_[REX][STATUS]//HTTP_NOT_FOUND)==HTTP_NOT_FOUND or $as_error;


          $path=$html_root."/".$p;
          #
          # First this is to report not found  and call next middleware
          # if the allow doesn't match (if a ignore exists)
          #
          next if($allow and $path !~ /$allow/o);

          next if($block and $path =~ /$block/o);




          Log::OK::TRACE and log_trace "static: html_root: $html_root";


          # File and Directory serving 
          #
          # Attempts to open the file and send it. If it fails, the next static
          # middleware is called if present


          my $entry;
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
                  my $ext=lc substr $_path, $index+1;
                  $content_type=$mime->{$ext}//$default_mime;
                  $path=$_path;
                  last;
                }
                else {
                  Log::OK::TRACE and log_trace "Static: did not locate index: $path";
                }
              }
            }

            #
            if($do_dir and !$entry){
              # Don't want an index file, just a dir listing
              #
              Log::OK::TRACE and log_trace "Static: Listing dir $p";
              #dir listing
              $_[PAYLOAD]=$p;   # hack
              $_[CB]=$next;     # hack
              #Push any user static headers
              #
              for my ($k, $v)(@$headers){
                $_[OUT_HEADER]{$k}=$v;
              }
              return $list_dir->(@_, $html_root, $p);
            }

            next unless $entry;
          }

          else {
            # Attempt a normal file serve
            #
            Log::OK::TRACE and log_trace "Working on opening normal file";
            my $index=rindex $path, ".";
            my $ext=lc substr $path, $index+1;
            $content_type=$mime->{$ext}//$default_mime;


            if($pre_encoded and ($_[IN_HEADER]{"accept-encoding"}//"")=~/(gzip)/){
              # Attempt to find a pre encoded file when the client asks and if its enabled
              #
              $enc=$1;
              my $enc_ext=$pre_encoded->{$1};
              $entry=$opener->($path.$enc_ext, $open_modes) if $enc_ext;
              unless($entry){
		Log::OK::TRACE and log_trace "NO Existing entry for opening file!";
                $entry=$opener->($path, $open_modes);
                $enc=($no_encoding and $ext=~/$no_encoding/)?"identity":"";

              }
	      else {
		      Log::OK::TRACE and log_trace "Existing entry for opening file!";
	      }
            }
            else{
              # No preencoded files enabled
              $entry=$opener->($path, $open_modes);
		Log::OK::TRACE and log_trace "Same entry? : ".$entry;
            }

            next unless($entry)
          }

          # Mark as path only if it looks like a template
          $path_only=$path =~ /$template/o if $template;

          unless($path_only){
            # Setup meta cache fields if they don't exist
            #
            unless($entry->[File::Meta::Cache::user_]){
              $entry->[File::Meta::Cache::user_]=[
                HTTP_CONTENT_TYPE, $content_type, 
                HTTP_LAST_MODIFIED, POSIX::strftime("%a, %d %b %Y %T GMT",
                  CORE::gmtime($entry->[File::Meta::Cache::stat_][9])),

                HTTP_ETAG, "\"$entry->[File::Meta::Cache::stat_][9]-$entry->[File::Meta::Cache::stat_][7]\"",
              ];
            }

            # Finally set the content encoding encountered along the way
            #

            $_[OUT_HEADER]{HTTP_CONTENT_ENCODING()}=$enc if $enc;

            # Push any user static headers common to this configuration
            #
            for my ($k, $v)(@$headers){
              $_[OUT_HEADER]{$k}=$v;
            }

            $ctx{$_[REX]}=[$entry, undef]; # Save this for error processing
            Log::OK::TRACE and log_trace __PACKAGE__."------SAVING CONTEXT before sending file $_[REX]";

            return send_file_uri(@_, $next, $read_size, $sendfile, $entry, $closer);
          }
          else {
            # Return the path in the payload,
            # Set the stats us undef, as the result needs to be rendered
            $_[REX][STATUS]=undef;
            $_[PAYLOAD]=$entry->[File::Meta::Cache::key_];
            $closer->($entry);
            return &$next;
          }
        }

		    Log::OK::DEBUG and log_debug "Could not find anything for $path in any root for rex:". $_[REX];
        # Didn't match anything in the roots.
        $_[PAYLOAD]="";
        $_[REX][STATUS]=HTTP_NOT_FOUND unless $as_error;

        $_[OUT_HEADER]{HTTP_CONTENT_LENGTH()}=0;
        $_[CB]=undef; # No more data to follow 
        &$next;
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


  my $error =sub {
    my $next=shift;
    sub {
      #

      #my @keys=map $_->[0], values %ctx;
      Log::OK::DEBUG and log_debug "---- STATIC ERROR MIDDLEWARE CALLED  for rex: $_[REX]";

      
      if($_[REX]){
        my $t=$ctx{$_[REX]};
        Log::OK::DEBUG and log_debug " calling reset on $_[REX] ...on sub:".$t->[1];
        $t->[1]->(); # Call the main sub with no args... which indicates error?
      }

      &$next;
    }
  };

  [$inner, $outer, $error];
  #[$outer, $inner];
}



sub uhm_static_file {
	my $path=uSAC::Util::path pop, [caller];
	my %options=@_;

	my $mime=$options{mime};
	my $type;
	if($mime){
		#manually specified mime type
		$type=$mime;
	}
	else{
    #my $ext=
    $options{extension}=substr $path, rindex($path, ".")+1;
	}

	if( stat $path and -r _ and !-d _){
    #my $entry;
		open my $fh, "<", $path;
		local $/;
    my $data=<$fh>;
		close $fh;

		#Create a static content endpoint
		uhm_static_content(%options, $data);
	}
	else {
    Log::OK::ERROR and log_error "Could not add hot path: $path";
	}
}

sub uhm_static_content {

  # First stage config
	my $static=pop;	#Content is the last item
	my %options=@_;

  [
    sub {
      # Second stage config
        my $next=shift;
        my $index=shift;
        my %ropts=@_;
        my $site=$ropts{site};

	      my $mime=
          $options{mime}
          //$site->resolve_mime_lookup->{$options{extension}}
          //$site->resolve_mime_default;

        my $headers=$options{headers}//{};

        $headers->{HTTP_CONTENT_TYPE()}||=$mime;

        $headers->{HTTP_CONTENT_LENGTH()}=length $static
          unless $headers->{HTTP_TRANSFER_ENCODING()};

        sub {
          if($_[OUT_HEADER]){
            for my  ($k, $v)(
              %$headers
            )
            { 
              $_[OUT_HEADER]{$k}=$v;
            }
            # Only set the payload when the out header is present (single shot)
            $_[PAYLOAD]=$static;
          }
          &$next;
        }
    }, 
    sub {
      my $next=shift;
    }
  ]
}


1;
