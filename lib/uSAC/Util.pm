package uSAC::Util;
use strict;
use warnings;
# Utility functions

use feature "say";

use Export::These qw( cwd dirname basename path catfile abs2rel rel2abs need);# decode_urlencoded_form);

sub cwd {
  my($dev, $inode)=stat ".";
  #my ($odev, $oinode)=($dev, $inode);

  my($prev_dev, $prev_inode)=(-1,-1);
  my @parts;
  until($prev_dev == $dev and $prev_inode == $inode){
      die $! unless chdir "..";

      my ($tdev, $tinode);

      ########################################################################
      # This is much nicer code, but requires alot more memory for code
      # for my $name (<*>){                                                  #
      #   ($tdev, $tinode)=lstat $name;                                      #
      #   push @parts, $name and last if($tdev == $dev and $tinode==$inode); #
      # }                                                                    #
      ########################################################################

      opendir my $dir, ".";
      my @list= readdir $dir;
      closedir $dir;
      
      #while(readdir $dir){
      for(@list){
        next if $_ eq "." or $_ eq "..";
        ($tdev, $tinode)=lstat;
        push @parts, $_ and last if($tdev == $dev and $tinode==$inode);
      }
      #closedir $dir;

      $prev_dev=$dev;
      $prev_inode=$inode;

      ($dev, $inode)=stat ".";
  }
  my $cwd="/".join "/", reverse @parts;
  chdir $cwd; #Change back
  $cwd
}

sub rel2abs {
  my $path=shift;
  my $base=shift||cwd;
  if($base !~ m|^/|){
    $base=abs2rel $base;
  }
  $base."/".$path;

}

sub abs2rel {
  my $abs=shift;
  my $base=shift||cwd;

  if($base !~ m|^/|){
    $base=abs2rel $base;
  }

  #find longest prefix
  my @base=split "/", $base;

  my $longest="";
  my $found=0;

  for(0..$#base){
    $longest=join "/", @base[0..$_];
    last if index $abs, $longest;
    $found++;
  }
  my $back_count=@base-$found;

  #strip off longest
  
  my $p=substr $abs,  length $longest;
  $p=join "/", ("..")x$back_count, $p;
  
  my @abs=split "/", $p;

  $p=substr $p, 1;
  # Prepend backcount

  #############################################################
  # my $index= index  $abs, $base;                            #
  #                                                           #
  # my @items=split "/", substr $abs, $index+length($base)+1; #
  # join "/", @items;                                         #
  #############################################################
  $p;

}

sub basename {
  my $path=shift;
  my @items = split "/", $path;
  pop @items;
}

sub dirname {
  my $path=shift;
  my @items = split "/", $path;
  my $p;
  if(@items>1){
    pop @items;
    $p=join "/", @items;
  }
  else {
    $p=".";# if @items == 1;
  }
  $p;
  
}


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

  
  my $cwd= cwd;#`realpath`;
  
  if(ref($_[0]) eq "SCALAR" or !defined $_[0]){
    $prefix=dirname abs2rel rel2abs $frame->[1];
    
    $p=$_[0]->$*;

    #Create the root as a relative path to current working dir
    if($p){
      return $p if $p =~ m|^/|;
      #$p=catfile($prefix, $p);
      $p="$prefix/$p";
    }
    else{
      # No suffix specified, don't join
      $p=$prefix;
    }
  }

  else {
    # Path is either CWD relative or absolute
    $p=$_[0];#$prefix;#$_[0];
  }

  if($p=~m|^/|){
    # ABS path. No nothing
  }
  elsif($p eq "."){
    $p="./"
  }
  elsif($p eq ".."){
    $p="../"
  }
  elsif($p!~m|^\.+/|){
    #relative path, but no leading dot slash. Add one to help 'require'
    $p="./".$p;
  }
  $p;
}

*usac_path=\&path;


my %needed;
sub need (*) {
  my $input=shift;
  my $frame=shift//[caller];

  # Resolve any relative to caller file paths
  # Wrapper around require. Exactly like require, exect the last value (the true value) is remembered
  my $res;
  my $key;

  my $path=$input;
  my $bare;
  for($path){
    # If the target contains :: or does not end with .pm, then 
    # assume it was a 'bare word' module
    if(!ref and (s|::|/|g or !/\./)){
      # Convert module name to path
      $key.=$_.".pm";
      $bare=1;
    }
    else{
      # Input is treated as path
      $key= path $input, $frame;
    }
  } 

  # Check the needed hash for the filename
  if(exists $needed{$key}){
    $res=$needed{$key};
  }
  else{
    if($bare){
      local $@;
      $res=eval "require $input;";
      die $@ if $@;
    }
    else {
      $res=require ($key);
      die "Could not require non bare word need" unless $res;
    }
    $needed{$key}=$res;
  }
  $res;
}


sub catfile {
  # Make sure no trailing slashses on components, then join
  join "/", map s|/$||, @_;
}

1;
