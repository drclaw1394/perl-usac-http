package uSAC::HTTP;
use strict;
use feature qw<say state refaliasing>;
use utf8;
use warnings;

use version; our $VERSION=version->declare("v0.1");
use Log::ger;
use Log::OK {
  lvl=>"info",
  opt=>"verbose",
};

# TODO: Event system to be via uSAC::IO eventually
use AnyEvent;

# HTTP constants for codes, methods and headers
use uSAC::HTTP::Code ":constants";
use uSAC::HTTP::Header ":constants";
use uSAC::HTTP::Method ":constants";

# Core of the uSAC::HTTP system
use uSAC::HTTP::Constants;  # Constants for the message structure of middleware
use uSAC::HTTP::Rex;        # Request and Response
use uSAC::HTTP::Site;       # Route grouping and base class
use uSAC::HTTP::Server;     # Main class to store routes and listen
#use uSAC::HTTP::Client;     # subclass for clients

# Common middleware
#
#use uSAC::HTTP::Middleware::Static;


# Contextual variables used in DSL
our $Site;


# Re-export any symbols that start with usac_, rex_ or certain  constants
#
sub import {
  my $caller=caller;
  strict->import;
  warnings->import;
  feature->import(qw<say state refaliasing current_sub>);
  #feature->unimport(qw<indirect>);
  utf8->import;

  #say join ", ", @_;
  if(@_==1){
    #Anything sub with usac or rex prefix is rexported
    #Also http constants and headers are rexported
    #
    for(keys %uSAC::HTTP::){
      #print $_."\n";
      no strict "refs";
      if( /^usac_/ or /^rex_/ or  /^HTTP_/ or /^uhm_/){
        *{$caller."::".$_}=\*{"uSAC::HTTP::".$_};
      }
      elsif(/Dir_Path/ or /File_Path/ or /Comp/ ){
        #print 'Symbol name: '.$_."\n";;
        s/\$//;
        my $name=$caller."::".$_;
        *{$name}=\${'uSAC::HTTP::Site::'.$_};
      }
    }
  }
  if(@_==1 or grep /:constants/, @_){
    #Export contants
    my $i=0;
    for(qw<ROUTE REX CODE HEADER PAYLOAD CB LF>){
      no strict "refs";
      my $name=$caller."::".$_;
      my $a=$i;
      #*{$name}=sub {$a};#\${'uSAC::HTTP::'.$_};
      *{$name}=\&{$_};
      $i++;
    }
  }
}
1;

=head1 NAME

uSAC::HTTP - Top Level HTTP Server and Client

uSAC::HTTP - Duct tape meets chainsaw

=head1 SYNOPSIS

  use uSAC::HTTP;
  usc uSAC::HTTP ":constants";

=head1 DESCRIPTION

A wrapper module which bundles multiple modules in the L<uSAC::HTTP>
distrubution,re exporting constants and subrotines and setting up the run time
environment.  It very quick to write high performance HTTP client and servers.






