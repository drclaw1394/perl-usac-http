package uSAC::Util;
use strict;
use warnings;
# Utility functions

#use File::Spec::Functions qw<catfile abs2rel rel2abs>;
#use File::Basename qw<dirname>;
use URL::Encode qw<url_decode_utf8>;
use feature "say";

use Export::These qw( cwd path decode_urlencoded_form);

sub TEST {
  say "IN TEST";
  say $_[0];

}
sub cwd {
  my($dev, $inode)=stat ".";
  my ($odev, $oinode)=($dev, $inode);

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
  #say "input: $abs";
  #say " base: $base";

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
  ##say "longest: $longest";
  #say "found: $found";

  #strip off longest
  
  my $p=substr $abs,  length $longest;
  $p=join "/", ("..")x$back_count, $p;
  
  my @abs=split "/", $p;

  $p=substr $p, 1;
  # Prepend backcount
  #say "RELATIVE: $p";

  #############################################################
  # my $index= index  $abs, $base;                            #
  #                                                           #
  # my @items=split "/", substr $abs, $index+length($base)+1; #
  # join "/", @items;                                         #
  #############################################################
  $p;

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
  # Poor mans dirname
  #my @items=split "/", abs2rel rel2abs($frame->[1]);

  ############################################################
  # my $abs=`realpath @{[$frame->[1]]}`;                     #
  # my $index= index  $abs, $cwd;                            #
  # my @items=split "/", substr $abs, $index+length($cwd)+1; #
  # pop @items;                                              #
  # $prefix=join "/", @items;                                #
  ############################################################
   
  
  if(ref($_[0]) eq "SCALAR" or !defined $_[0]){
    ########################################################################
    # say "FRAME: $frame->[1]";                                            #
    # say "CWD: ".cwd;                                                     #
    # say "rel2abs ". rel2abs $frame->[1];                                 #
    # say "abs2rel rel2abs ". abs2rel rel2abs $frame->[1];                 #
    # say "dirname abs2rel rel2abs ". dirname abs2rel rel2abs $frame->[1]; #
    ########################################################################
    $prefix=dirname abs2rel rel2abs $frame->[1];
    
    $p=$_[0]->$*;
    return $p if $p =~ m|^/|;

    #Create the rool as a relative path to current working dir
    if($p){
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
  elsif($p!~m|^\.+/|){
    #relative path, but no leading do slash. Add one to help 'require'
    $p="./".$p;
  }
  $p;
}

*usac_path=\&path;

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
sub catfile {
}
1;
