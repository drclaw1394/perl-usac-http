package uSAC::HTTP::Client;
use Log::ger;
use Object::Pad;

class uSAC::HTTP::Client :isa(uSAC::HTTP::Server);
use feature "say";


field $_host_pool_limit :param=undef;


BUILD {
  $self->mode=1;          # Set mode to client.
  $_host_pool_limit//=5;  # limit to 5 concurrent connections by default

}

method stop {

}

method run {
  #my $self=shift;
  my $sig; $sig=AE::signal(INT=>sub {
          $self->stop;
          $sig=undef;
  });

	$self->rebuild_dispatch;

  if($self->options->{show_routes}){
    Log::OK::INFO and log_info("Routes for selected hosts: ".join ", ", $self->options->{show_routes}->@*);
    $self->dump_routes;
    #return;
  }
	Log::OK::TRACE and log_trace(__PACKAGE__. " starting client...");
}
1;
