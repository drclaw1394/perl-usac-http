package uSAC::HTTP::Client;
use Log::ger;
use Object::Pad;

class uSAC::HTTP::Client :isa(uSAC::HTTP::Server);
use feature "say";


field $_host_pool_limit :param=undef;
field $_cookie_jar_path :param=undef;


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


# Like clicking the link
# Uses the current url page as referer if enabled
# Treats request as httpOnly (non script)
#
method follow_link {

}

# Typing the address or clicking a shortcut. No referer
# of current page
#
method go {

}

# As per fetch api?
#
method fetch ($resource, $options){

}


1;
