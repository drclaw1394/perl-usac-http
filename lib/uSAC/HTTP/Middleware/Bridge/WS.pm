package uSAC::HTTP::Middleware::Bridge::WS;
use v5.36;

use Log::OK;
use uSAC::Log;
use uSAC::HTTP;
use uSAC::HTTP::Middleware::Websocket;

use Data::Dumper;

use Export::These qw<uhm_bridge_ws>;

# Turns the session into a ws bridge
sub uhm_bridge_ws{
  my %options=@_;

  # Here we can specify a specifiy broker
  my $broker=$options{broker};

  # Topic matchers /type pairs to forward immediately
  my $forward=$options{forward}//[];

  (
    uhm_websocket(),
    [sub {
        my ($next, $index, $site)= $_[0];
        
        # If external broker not set, find the closes one in site hierrachy
        $broker//=$site->broker;

        # Lastley,, we just make our own... 
        $broker//=uSAC::FastPack::Broker->new();
        
        sub {
          my $bridge;
          my $ws=$_[PAYLOAD];
          
          $ws->on_open=sub {
            # Create a new bridge
            #
            $bridge=uSAC::FastPack::Broker::Bridge->new(broker=>$broker);

            # Set the the output sub BERFORE listening
            $bridge->buffer_out_sub=sub { Log::OK::TRACE and log_trace , "--CALLIND BUFFER OUT on ws $ws"; $ws->send_binary_message($_[0][0]); };

            # Access the forwarding sub to force linking
            $bridge->forward_message_sub;

            ## Forward messages form the local broker across the bridge, unless the message originated from the bridge
            # When a bridge is used as the callback, it the forwarding sub and client id is used automatically
            #
            #$broker->listen(undef, "test",    $bridge); 
            #$broker->listen(undef, "return",  $bridge); 

            # Add the initial forwarding 
            for my ($matcher, $type)(@$forward){
              $broker->listen(undef, $matcher,  $bridge, $type); 
            }

            
            $_[PAYLOAD]=[$broker, $bridge];
            &$next;

          };

          $ws->on_message=sub {
            Log::OK::TRACE and log_trace  Dumper $_[1];
            $bridge->on_read_handler->([$_[1]]);
          };

          $ws->on_close=sub {
            Log::OK::TRACE and log_trace  "WEBSOCKET CLOSED";
            $ws->destroy;
            $bridge->close;
            $broker->ignore("$ws",undef, undef,undef,"sub matcher"); #Remove all entires with client id 
            $ws=undef;
          };

        }
        
      }
    ]
  )
}

1;
