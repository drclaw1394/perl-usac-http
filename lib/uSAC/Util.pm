package uSAC::Util;
# Utility functions

use File::Spec::Functions qw<catfile abs2rel>;
use File::Basename qw<dirname>;
use Cwd qw<abs_path>;
use Exporter "import";

our @EXPORT_OK=qw(
  path
);
our @EXPORT=@EXPORT_OK;

# Process a path.  If a ref, make relative to caller dir if abs leave as it if
# relative leave as is Optional second argument specifiy caller frame. If no
# proveded is assumed to be direct caller of thsi sub
sub path {
    
  my $p;
  my $prefix;
  my $frame=$_[1]//[caller];
  if(ref($_[0]) eq "SCALAR"){
    
    $p=$_[0]->$*;
    return $p if $p =~ m|^/|;
    #Create the roolt as a relative path to current working dir
	  $prefix=dirname abs2rel abs_path($frame->[1]);
    $p=catfile($prefix,$p);
    
  }
  else {
    $p=$_[0];
  }

  if($p=~m|^/|){
    # ABS path. No nothing
  }
  elsif($p!~m|^\.+/|){
    #relative path, but no leading do slash. Add one to help 'require'
    $p="./".$p;
  }
  $p;
}

*usac_path=\&path;

1;
