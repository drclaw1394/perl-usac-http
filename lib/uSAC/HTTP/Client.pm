package uSAC::HTTP::Client;

use Object::Pad;
class uSAC::HTTP::Client :isa(uSAC::HTTP::Server);
use feature "say";


field $_host_pool_limit :param=undef;


BUILD {
  $self->mode=1;          # Set mode to client.
  $_host_pool_limit//=5;  # limit to 5 concurrent connections by default

}



1;
