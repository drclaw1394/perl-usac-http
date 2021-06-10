package uSAC::HTTP::Server::Session;

#Class attribute keys
use enum ( "id_=0" ,qw<fh_ closeme_ rw_ ww_ wbuf_ left_ on_body_>);

#Add a mechanism for sub classing
use constant KEY_OFFSET=>0;
use constant KEY_COUNT=>on_body_-id_+1;

1;
