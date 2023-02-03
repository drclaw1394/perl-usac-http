use strict;
use warnings;
use feature qw<state say>;


use EV;
use AnyEvent;

use uSAC::HTTP;
use uSAC::HTTP::Middleware qw<log_simple>;
use uSAC::HTTP::Middleware::Websocket qw<websocket>;

use Log::ger::Output "Screen";

my %clients;

my $server=uSAC::HTTP::Server->new();

#FIXME:
#the listeners and hosts needs to be setup before adding routes

$server->add_listeners( "127.0.0.1:9090");
#$server->add_host("localhost:9090");
$server->set_mime_default;
$server->add_middleware(log_simple);

$server->add_route('GET'=>"/\$"=>sub {
	local $/=undef; state $data; $data=<DATA> unless $data;	

	#TODO: bug. <> operator not working with state
  $_[PAYLOAD]=$data;	
	&rex_write;
});




$server->add_route(GET=>"/ws"=> websocket()=>sub{
		my ($matcher, $rex, $code, $headers, $ws)=@_;
		say " IN usac websocket  callback: ",join ", ", @_;
		my $timer;
		#$ws->ping_interval(0);
    $ws->on_open=sub {
      $clients{$_[0]}=$_[0];
      $timer=AE::timer 0, 1, sub {
        $ws->send_text_message("hello",sub {
            say "CALLBACK";
          });
      };
    };

		$ws->on_message=sub {
				say "GOT message: $_[1]";
				while(my($id, $client)=each  %clients){
					$client->send_text_message("hello") unless $client==$_[0];
				}
			};

		$ws->on_error=sub {
				say "GOT error$_[0]";
			};

		$ws->on_close=sub {
				say "GOT close";
				undef $timer;
			};

	}
);

$server->add_route("GET"=>"/large"=>()=>sub {
	state $data= "x"x(4096*4096);
  $_[PAYLOAD]=$data;
	&rex_write;
});

$server->add_route("GET"=>"/chunks"=>()=>sub {
	state $data= "x" x (4096*4096);
	my $size=4096*1;
	my $offset=0;#-$size;;
	my @g=@_;

  my @args=@_;
	my $sub;
  $sub=sub {
		my $d=substr($data, $offset, $size);	#Data to send

		$offset+=$size;				#update offset
    #rex_write @g, $data, $offset<length($data)?__SUB__:undef;
		
    if($offset<length($data)){
        $args[PAYLOAD]= substr $data, $offset, $size;
        $args[CB]=__SUB__;
    }
    else {
      $args[PAYLOAD]= "";
      $args[CB]=undef;
      $sub=undef;
    }

    rex_write @args;
	};

	$sub->();
});

$server->parse_cli_options(@ARGV);
$server->run;

__DATA__
<html>
	<head>
		<title>Websocket test </title>
	</head>
	<body>
    <div id="messages"></div>
		<script >
      let messages=document.getElementById("messages");
			
			var ws=new WebSocket("ws://"+location.host+"/ws","chat");
			var id=Date.now();
			ws.onopen=function(event){
				console.log("websocket open");
				//ws.send("hello");

				setInterval(function(){
					ws.send(id+" hello");
				},100);
			};

			ws.onmessage= function(msg){
				console.log("websocket message",msg.data);
        let m= document.createElement("div");
        m.innerHTML=msg.data;
        messages.appendChild(m);
				};
			ws.onerror= function(msg){
				console.log("websocket error",msg);
			};
		</script>

	</body>
<html>

