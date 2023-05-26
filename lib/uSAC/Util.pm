package uSAC::Util;
# Utility functions

use File::Spec::Functions qw<catfile abs2rel>;
use File::Basename qw<dirname>;
use Cwd qw<abs_path cwd>;
use Exporter "import";
use feature "say";

our @EXPORT_OK=qw(
  path
);
our @EXPORT;#=@EXPORT_OK;

# Process a path.  
# If a ref and defined, make relative to caller dir
# If a ref and undefined, is caller dir
# if a ref and abs leave as it is
# if not a ref and defined make relative to cwd
# if not a ref and undefined is cwd
# if not a ref and abs leave as it is
#
# Optional second argument specifiy caller frame. If none proveded is
# assumed to be direct caller of this sub
# 
sub path {
  my $p;
  my $prefix;
  my $frame=$_[1]//[caller];
	$prefix=dirname abs2rel abs_path($frame->[1]);
  if(ref($_[0]) eq "SCALAR"){
    
    $p=$_[0]->$*;
    return $p if $p =~ m|^/|;
    #Create the roolt as a relative path to current working dir
    if($p){
      $p=catfile($prefix,$p);
    }
    else{
      # No suffix specified, don't join
      $p=$prefix;
    }
  }
  elsif(!defined $_[0]){
    # If undefined, then we just want current working dir
    $p=cwd;
  }
  else {
    # Path is either CWD relative or absolute
    $p=$_[0];#$prefix;#$_[0];
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
