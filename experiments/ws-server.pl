use strict;
use warnings;
use feature qw<state say>;

use Log::ger;
use Log::ger::Output "Screen";
use Log::OK {
	lvl=>"warn",
	opt=>"verbose"
};
Log::ger::Util::set_level Log::OK::LEVEL;

use EV;
use AnyEvent;

use uSAC::HTTP;
use uSAC::HTTP::Middleware qw<log_simple>;
use uSAC::HTTP::Server::WS;

my %clients;


my $server=uSAC::HTTP::Server->new();

#FIXME:
#the listeners and hosts needs to be setup before adding routes

$server->add_listener( "127.0.0.1:9090");
$server->add_host("localhost:9090");
$server->set_mime_default;
$server->add_middleware(log_simple);

$server->add_route('GET'=>"/\$"=>sub {
	local $/=undef; state $data; $data=<DATA> unless $data;	

	#TODO: bug. <> operator not working with state
	
	rex_write(@_, $data);
	return;
});




$server->add_route(GET=>"/ws"=> usac_websocket sub{
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
	rex_write @_, $data;
});

$server->add_route("GET"=>"/chunks"=>()=>sub {
	state $data= "x" x (4096*4096);
	my $size=4096*128;
	my $offset=0;#-$size;;
	my @g=@_;

	my $sub=sub {
		my $d=substr($data, $offset, $size);	#Data to send

		$offset+=$size;				#update offset
		rex_write @g, $data, $offset<length($data)?__SUB__:undef;
		
	};
	$sub->();
});


$server->run;

__DATA__
<html>
	<head>
		<title>WS test </title>
	</head>
	<body>
		<script >
			
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
				};
			ws.onerror= function(msg){
				console.log("websocket error",msg);
			};
		</script>

	</body>
<html>
