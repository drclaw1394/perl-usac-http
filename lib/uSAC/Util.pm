package uSAC::Util;
# Utility functions

use File::Spec::Functions qw<catfile abs2rel rel2abs>;
use File::Basename qw<dirname>;
use URL::Encode qw<url_decode_utf8>;
use feature "say";

use Export::These qw( path decode_urlencoded_form);

# Process a path.  
# If a ref and defined, make relative to caller dir
# If a ref and undefined, is caller dir
# if a ref and abs leave as it is
# if not a ref and defined make relative to cwd
# if not a ref and undefined is relative caller dir
# if not a ref and abs leave as it is
#
# Optional second argument specifiy caller frame. If none proveded is
# assumed to be direct caller of this sub
# 
sub path {
  my $p;
  my $prefix;
  my $frame=$_[1]//[caller];
	$prefix=dirname abs2rel rel2abs($frame->[1]);
  if(ref($_[0]) eq "SCALAR" or !defined $_[0]){
    
    $p=$_[0]->$*;
    return $p if $p =~ m|^/|;
    #Create the rool as a relative path to current working dir
    if($p){
      $p=catfile($prefix, $p);
    }
    else{
      # No suffix specified, don't join
      $p=$prefix;
    }
  }

  ###########################################################
  # elsif(!defined $_[0]){                                  #
  #   # If undefined, then we just want current working dir #
  #   #$p=cwd;                                              #
  #   $p=rel2abs(".");                                      #
  # }                                                       #
  ###########################################################
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

#parse a form in either form-data or urlencoded.
#First arg is rex
#second is data
#third is the header for each part if applicable
sub decode_urlencoded_form {
  my %kv;
  for(split "&", url_decode_utf8 $_[0]){
    my ($k, $v)=split "=", $_, 2;
    if(!exists $kv{$k}){
        $kv{$k}=$v;
    }
    elsif(ref $kv{$k}){
      push $kv{$k}->@*, $v; 
    }
    else {
      $kv{$k}=[$kv{$k}, $v];
    }
  }
  \%kv;
}
1;
