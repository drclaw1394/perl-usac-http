package uSAC::HTTP;
use v5.36;

our $VERSION="v0.1.0";

# Preload the core
use uSAC::HTTP::Site ();
use uSAC::HTTP::Rex ();
use uSAC::HTTP::Header ();
use uSAC::HTTP::Code ();
use uSAC::HTTP::Constants ();
use uSAC::HTTP::Route ();
use uSAC::MIME;

# Generate import sub and support reexport
#
use Export::These;

# Contextual variables used in DSL
#
our $Site;

# Called from Export::These hook. $target is the package of the importer
# of this module. Works at any level  with Export::These
#
sub _reexport {
  my ($pack, $target)=(shift,shift);
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

  uSAC::HTTP::Site->import;
  uSAC::HTTP::Rex->import;
  uSAC::HTTP::Header->import;
  uSAC::HTTP::Code->import;
  uSAC::HTTP::Constants->import;
  uSAC::HTTP::Route->import;
  uSAC::MIME->import;
  
}

__PACKAGE__;


=head1 NAME

uSAC::HTTP - Duct Tape x Chainsaw

=head1 SYNOPSIS

  use uSAC::HTTP;

=head1 DESCRIPTION

A wrapper module which bundles multiple modules in the L<uSAC::HTTP>
distrubution,re exporting constants and subrotines and setting up the run time
environment.  It very quick to write high performance HTTP client and servers.






