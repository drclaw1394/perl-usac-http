package uSAC::HTTP::FileMetaCache;
use Object::Pad;
class uSAC::HTTP::FileMetaCache;
use feature "say";

use AnyEvent;   # TODO: abstract away...
use IO::FD;     # For IO
use Log::ger;   # Logger
use Log::OK;    # Logger enabler
use uSAC::HTTP::Header qw<:constants>;

use POSIX();

# Default Opening Mode
use Fcntl qw(O_NONBLOCK O_RDONLY);
use constant OPEN_MODE=>O_RDONLY|O_NONBLOCK;
use enum qw<fh_ content_type_header_ size_ mt_ last_modified_header_ content_encoding_ cached_ key_ etag_>;


field $_html_root :param;
field $_sweep_size; # :param;
field $_sweep_interval;# :param;
field $_mime  :param;
field $_default_mime :param;
field $_timer;
field %_cache;
field $_opener;
field $_closer;

BUILD{
  $_sweep_interval//=5;
  $_sweep_size//=100;
}
my %encoding_map =(
	gz=>"gzip",
);

# returns a sub to execute. Object::Pad method lookup is slow. so bypass it
# when we don't need it
#
method opener{
  $_opener//=
  sub {
    my ( $abs_path, $mode, $pre_encoded)=@_;
    my $in_fh;
    my $enc_path;

    my $entry=$_cache{$abs_path};
    unless($entry){
      for my $pre (@$pre_encoded,""){

        my $path= $abs_path.($pre?".$pre":"");

        Log::OK::TRACE and log_trace "Static: Searching for: $path";

        next unless stat($path) and -r _ and ! -d _; #undef if stat fails

        # Lookup mime type
        #
        my $ext=substr $abs_path, rindex($abs_path, ".")+1;

        my @entry;
        $entry[content_type_header_]=[HTTP_CONTENT_TYPE, ($_mime->{$ext}//$_default_mime)];
        $entry[size_]=(stat _)[7];
        $entry[mt_]=(stat _)[9];
        $entry[key_]=$abs_path;

        if($pre){
          $entry[content_encoding_]=[HTTP_CONTENT_ENCODING, $encoding_map{$pre}];
        }
        else{
          $entry[content_encoding_]=[];
        }

        if(defined IO::FD::sysopen $in_fh, $path, OPEN_MODE|($mode//0)){
          #say $in_fh;
          #open $in_fh,"<:mmap", $path or return;
          $entry[fh_]=$in_fh;
          Log::OK::DEBUG and log_debug "Static: preencoded com: ".$pre;
          Log::OK::TRACE and log_trace "content encoding: ". join ", ", $entry[content_encoding_]->@*;
          #my $tp=gmtime($entry[mt_]);
          my @time=CORE::gmtime($entry[mt_]);

          #$entry[last_modified_header_]=[HTTP_LAST_MODIFIED, $tp->strftime("%a, %d %b %Y %T GMT")];
          $entry[last_modified_header_]=[HTTP_LAST_MODIFIED, POSIX::strftime("%a, %d %b %Y %T GMT",@time)];
          $entry[etag_]="\"$entry[mt_]-$entry[size_]\"";
          $entry[cached_]=1;

          $entry=\@entry;

          # Cache the entry only if cache is enabled
          if($_timer){
            $_cache{$abs_path}=$entry;
          }

        }
        else {
          Log::OK::ERROR and log_error " Error opening file $abs_path: $!";
        }
      }
    }
    #Log::OK::WARN and log_warn "Could not open file $abs_path";
    
    $entry->[cached_]++ if $entry;
    $entry;
  }
}

# Kill the timer, close all file handles and empty the cache
method disable{
  $_timer=undef;
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

# Create a timer which checks for any file changes (if enabled)
# and closes the fd if nothing is referencing it and 
method enable{
  unless ($_timer){
    $_timer=AE::timer 0, $_sweep_interval, sub {
      #say "Doing timer";
      my $i=0;
      my $entry;
      my $closer=$self->closer;
      for(keys %_cache){
        $entry=$_cache{$_};

        # If the cached_ field reaches 1, this is the last code to use it. so close it
        # 
        #say "Timer for entry: $entry->[key_]";
        $closer->($entry) if($entry->[cached_]==1);
        last if ++$i >= $_sweep_size;
      }
    };
  }
}

1;

=head1 NAME

uSAC::HTTP::FileMetaCache - File Meta Data Cache

=head1 SYNOPSIS

  use uSAC::HTTP::FileMetaCache;

  my $cache=uSAC::HTTP::FileMetaCache->new(html_root=>"...");
  $cache->enable;
  my $opener=$cache->opener;
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

