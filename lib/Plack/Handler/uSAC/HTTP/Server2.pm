package Plack::Handler::uSAC::HTTP::Server2;
use strict;
use warnings;
use feature qw<refaliasing>;
use uSAC::Log;
# Wrapper for running asyncrhomous usac based servers
use v5.36;

sub new {
  my ($class, %options)=@_;
  use Data::Dumper;
  bless \%options, $class;
  
}

sub  run {
  my ($self,$app)=@_;
  # build up the command line for exec

  ###################################
  # my $file=__FILE__;              #
  # use File::Basename qw<dirname>; #
  # $file=dirname $file;            #
  # $file=$file."/Server.pm";       #
  ###################################

  my @cmd=("usac-http-server");
  push @cmd, "--backend";
  my $backend=$self->{backend}//"AnyEvent";
  push @cmd, $backend;

  if ($self->{listen}){
    #push @cmd, map {("--listen", $_)} $self->{listen}->@*;
  }
  else {
    push @cmd, "--listen", "a=$self->{host},po=$self->{port},t=stream";
  }
  
  push @cmd, "--workers", $self->{workers}//$self->{max_workers} if defined($self->{workers}) or defined($self->{max_workers});


  #exec
  exec @cmd;

}

1;
