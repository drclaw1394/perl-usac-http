package uSAC::HTTP;
use warnings;
use strict;

use version; our $VERSION=version->declare("v0.1");

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
  strict::import($target);

  require warnings;
  warnings::import($target);

  require feature;
  feature::import($target,qw<say state refaliasing current_sub>);
  feature::unimport($target,qw<indirect>);

  require utf8;
  utf8::import($target);

  require uSAC::HTTP::Site;
  uSAC::HTTP::Site::import($target);

  require uSAC::HTTP::Rex;
  uSAC::HTTP::Rex::import($target);

  require uSAC::HTTP::Header;
  uSAC::HTTP::Header::import($target);

  require uSAC::HTTP::Code;
  uSAC::HTTP::Code::import($target);
  
  require uSAC::HTTP::Constants;
  uSAC::HTTP::Constants::import($target);
  
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






