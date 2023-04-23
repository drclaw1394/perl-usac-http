#
# IMPORTANT 
#
# Middleware must pass 6 argument along the chain
#
#   route, rex, code, header, payload, cb
#
# As most of the uSAC api utiliseds the @_ array, it is very important to keep the count correct.
#
# route and rex must alway be defined and set by the parser at the start of the chain
# 
# code can be any non zero, valid http code for normal processing (a true value)
# when code is false, it triggers a stack reset all the way down to the output writer
#
# header must be a has ref, even an empty one, for the start of a request. Middleware
# further down the line will set this to undef when it has started its 'accumualted' output.
# ie the serializer will do this, on the fly zip, gzip compression will also do this.
#
# payload is the data to send to the next middleware component. It is normally
# string content, but does not have to be
#
# callback is the sub ref to call when the 'accumulator' has processed the data
# chunk. When it is undef, in indicates the upstream middleware does not need
# notifificaiton and has finished. This the instruct the acculuator to
# performan any finishing work, and potentailly call futher middleware
#
# It is also important that each of the above are lvalues, not constants. This
# is because middleware stages might write to the (aliased) variable which will
# continue to be used for subsequent middleware. Of course you can compy the
# arguments however that causes a performance hit
#
package uSAC::HTTP::Middleware;
use strict;
use warnings;

use Log::ger;
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
