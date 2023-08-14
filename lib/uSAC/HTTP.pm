package uSAC::HTTP;
use v5.36;

our $VERSION="v0.1.0";

# Preload the core
use Import::These "uSAC::HTTP::", 
  Site=>[], Rex=>[], Header=>[],
  Code=>[], Constants=>[], Route=>[];

use uSAC::MIME;

our $Site;   

# Generate import sub and support reexport
#
use Export::These;

# Called from Export::These hook. $target is the package of the importer
# of this module. Works at any level  with Export::These
#
sub _reexport {
  my ($pack, $target)=(shift, shift);
  # The following manipulate hints, so the caller is irrelevant
  #
  require strict;
  strict->import;

  require warnings;
  warnings->import;

  require feature;
  feature->import(qw<say state refaliasing current_sub>);
  feature->unimport(qw<indirect>);
  

  require utf8;
  utf8->import;

  Import::These->import(qw<uSAC::HTTP:: Site Rex Header Code Constants Route>);
  ##################################
  # uSAC::HTTP::Site->import;      #
  # uSAC::HTTP::Rex->import;       #
  # uSAC::HTTP::Header->import;    #
  # uSAC::HTTP::Code->import;      #
  # uSAC::HTTP::Constants->import; #
  # uSAC::HTTP::Route->import;     #
  ##################################
  uSAC::MIME->import;
  
}

__PACKAGE__;


=head1 NAME

uSAC::HTTP - Duct Tape x Chainsaw

=head1 SYNOPSIS

  
  #For servers
  use uSAC::HTTP::Server;

  #For clients
  use uSAC:HTTP::Client;


=head1 DESCRIPTION


This is grouping of core L<uSAC::HTTP> data structures and modules to write
HTTP like client and server alpplications.

Normally you would import the server or client (or both) to add it to your
application.


This is very much unfinished and under heavy development and changes....
