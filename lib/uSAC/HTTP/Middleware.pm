# Please refere to the pod file for important documentation !!!
# jj
package uSAC::HTTP::Middleware;
use strict;
use warnings;

use uSAC::Log;
use Log::OK;

use Exporter 'import';
use feature qw<refaliasing say state>;
no warnings "experimental";

#no feature "indirect";
#use uSAC::HTTP::Session;
use uSAC::HTTP::Code qw<:constants>;
use uSAC::HTTP::Header qw<:constants>;
use uSAC::HTTP::Rex;
use uSAC::HTTP::Constants;

our @EXPORT_OK=qw< bypass >;
our @EXPORT=();
our %EXPORT_TAGS=(
	"all"=>[@EXPORT_OK]
);



sub bypass {
  sub {
    my $next=shift;
    $next;
  }
}




1;
