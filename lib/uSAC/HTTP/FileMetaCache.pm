use strict;
use warnings;
package uSAC::HTTP::FileMetaCache;
use Object::Pad;
class uSAC::HTTP::FileMetaCache;
use feature qw<say state>;

#use AnyEvent;   # TODO: abstract away...
use IO::FD;     # For IO
use Log::ger;   # Logger
use Log::OK;    # Logger enabler
use uSAC::HTTP::Header qw<:constants>;

use POSIX();

# Default Opening Mode
use Fcntl qw(O_NONBLOCK O_RDONLY);
use constant OPEN_MODE=>O_RDONLY|O_NONBLOCK;
use enum qw<fh_ content_type_header_ size_ mt_ last_modified_header_ content_encoding_ cached_ key_ etag_ source_ user_>;


#field $_html_root :param;
field $_sweep_size; # :param;
#field $_sweep_interval;# :param;
field $_mime_table  :param; 
field $_default_mime :param;
field $_timer;
field $_enabled;
field $_sweeper;
field %_cache;
field $_opener;
field $_closer;
field $_http_headers;

BUILD{
  #$_sweep_interval//=5;
  $_sweep_size//=100;
  $_enabled=1;
}

method sweeper {
  $_sweeper//= sub {
    my $i=0;
    my $entry;
    my $closer=$self->closer;
    for(keys %_cache){
      $entry=$_cache{$_};

      # If the cached_ field reaches 1, this is the last code to use it. so close it
      # 
      $closer->($entry) if($entry->[cached_]==1);
      last if ++$i >= $_sweep_size;
    }
  }
}

# returns a sub to execute. Object::Pad method lookup is slow. so bypass it
# when we don't need it
#
method opener{
  $_opener//=
  sub {
    my ( $key_path, $mode, $suffix_list)=@_;
    my $in_fh;

    # Entry is identified by the path, however, the actual data can come from another file
    # 
    my $entry=$_cache{$key_path};

    unless($entry){
      #for my $suffix (@$suffix_list){

      #my $path=$key_path.$suffix;

        Log::OK::TRACE and log_trace "Static: Searching for: $key_path";

        return unless stat($key_path) and -r _ and ! -d _; #undef if stat fails

        my @entry;
        
        $entry[size_]=(stat _)[7];
        $entry[mt_]=(stat _)[9];
        $entry[key_]=$key_path;

        if(defined IO::FD::sysopen $in_fh, $key_path, OPEN_MODE|($mode//0)){
          $entry[fh_]=$in_fh;
          #Log::OK::DEBUG and log_debug "Static: preencoded com: ".$suffix ;
          #Log::OK::TRACE and log_trace "content encoding: ". join ", ", $entry[content_encoding_]->@*;
          $entry[cached_]=1;

          $entry=\@entry;
          $_cache{$key_path}=$entry if($_enabled);

        }
        else {
          Log::OK::ERROR and log_error " Error opening file $key_path: $!";
        }
        #}
    }

    # Increment the  counter 
    #
    $entry->[cached_]++ if $entry;
    $entry;
  }
}


# Mark the cache as disabled. Dumps all values and closes
# all fds
#
method disable{
  $_enabled=undef;
  #$_timer=undef;
  for(values %_cache){
    IO::FD::close $_cache{$_}[0];
  }
  %_cache=();
}

# Generates a sub to close a cached fd
# removes meta data from the cache also
#
method closer {
  $_closer//=sub {
      my $entry=$_[0];
      #say "Closer called: ".$entry->[cached_];
      if(--$entry->[cached_] <=0){
        IO::FD::close $entry->[fh_]; 
        delete $_cache{$entry->[key_]};
      }
  }
}

# OO Interface
#

method open {
  state $opener=$self->opener;
  &$opener;
}

method close {
  state $closer=$self->closer;
  &$closer;
}

# Create a timer which checks for any file changes (if enabled)
# and closes the fd if nothing is referencing it and 
#
method enable{
  $_enabled=1;

  ########################################################################################
  # unless ($_timer){                                                                    #
  #   $_timer=AE::timer 0, $_sweep_interval, sub {                                       #
  #     #say "Doing timer";                                                              #
  #     my $i=0;                                                                         #
  #     my $entry;                                                                       #
  #     my $closer=$self->closer;                                                        #
  #     for(keys %_cache){                                                               #
  #       $entry=$_cache{$_};                                                            #
  #                                                                                      #
  #       # If the cached_ field reaches 1, this is the last code to use it. so close it #
  #       #                                                                              #
  #       #say "Timer for entry: $entry->[key_]";                                        #
  #       $closer->($entry) if($entry->[cached_]==1);                                    #
  #       last if ++$i >= $_sweep_size;                                                  #
  #     }                                                                                #
  #   };                                                                                 #
  # }                                                                                    #
  ########################################################################################
}

1;

=head1 NAME

uSAC::HTTP::FileMetaCache - File Meta Data Cache

=head1 SYNOPSIS

  use uSAC::HTTP::FileMetaCache;

  # Create a cache object
  #
  my $cache=uSAC::HTTP::FileMetaCache->new(%options);
  
  # Optionally setup a timer in your event system to sweep the cache
  # AnyEvent shown
  #
  state $timer = AE::timer 0, 1, $cache->sweeper;

  # Create a opener sub
  #
  my $opener=$cache->opener;
  $cache->enable;

  my $entry=$opener->($path);



=head1 DESCRIPTION

Provides caching of file meta data, but not content. File size, etag, content
type and times are all read/generated when a file is opened with an opener.

On subsequent open operations, if the entry matching the path is found in the
cache, the refernce to that entry is increase, and the refernce is returned.

This dramatically increases the usability of a file, as it avoids the long time
it takes to open a file.

Must use seek sysread/syswrite or pread/pwrite, as the filedescriptor is shared
with other parts of the program.


Uses relative paths for faster opening times

