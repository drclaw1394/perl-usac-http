package uSAC::HTTP;
use warnings;
use strict;

use version; our $VERSION=version->declare("v0.1");

use uSAC::HTTP::Site ();
use uSAC::HTTP::Rex ();
use uSAC::HTTP::Header ();
use uSAC::HTTP::Code ();
use uSAC::HTTP::Constants ();
use uSAC::HTTP::Route ();

# Generate import sub and support reexporting
#
use Export::These;

# Contextual variables used in DSL
#
our $Site;

# Called from Export::These hook. $target is the package of the importer
# of this module. Works at any level  with Export::These
#
sub _reexport {
  my $target=shift;
  # The following manipulate hints, so the caller is irrelevant
  #
  require strict;
  strict->import;#($target);

  require warnings;
  warnings->import;#($target);

  require feature;
  feature->import(qw<say state refaliasing current_sub>);
  feature->unimport(qw<indirect>);

  require utf8;
  utf8->import;#($target);

  print "\nExport level HTTP: ".$Exporter::ExportLevel;
  print "\n";
  uSAC::HTTP::Site->import;

  uSAC::HTTP::Rex->import;

  uSAC::HTTP::Header->import;

  uSAC::HTTP::Code->import;
  
  uSAC::HTTP::Constants->import;

  uSAC::HTTP::Route->import;
  
}

__PACKAGE__;


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






