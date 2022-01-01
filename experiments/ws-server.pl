use strict;
use warnings;
use feature qw<state say signatures>;

use uSAC::HTTP;
use uSAC::HTTP::Server::WS;
use AnyEvent;

my %clients;



my $server=uSAC::HTTP::Server->new(
	host=>"0.0.0.0",
	port=>8080,
);

$server->add_route('GET'=>"/\$"=>sub {
	local $/=undef; state $data; $data=<DATA> unless $data;	

	#TODO: bug. <> operator not working with state
	
	rex_reply_simple(@_, HTTP_OK, [], $data);
	return;
});

$server->add_route(GET=>"/ws"=> usac_websocket sub($ws){
		my $timer;
		$ws->ping_interval(0);
		$ws->on_open=sub {
			$clients{$_[1]}=$_[0];
                        ################################################
                        #  $timer=AE::timer 0, 1, sub {                #
                        #         $ws->send_text_message("hello",sub { #
                        #                 say "CALLBACK";              #
                        #         });                                  #
                        # };                                           #
                        ################################################
		};

		$ws->on_message=sub {
				say "GOT message: $_[2]";
				while(my($id,$client)=each  %clients){
					$client->send_text_message($_[2]) unless $id==$_[1];
				}
			};

		$ws->on_error=sub {
				say "GOT error$_[0]";
			};

		$ws->on_close=sub {
				say "GOT close";
				undef $timer;
			};

		say "GOT WEBSOCKET ", $_[0];
	}
);

$server->add_route("GET"=>"/large"=>()=>sub {
	state $data= "x"x(4096*4096);
	rex_reply_simple @_,HTTP_OK,undef,$data;
});

$server->add_route("GET"=>"/chunks"=>()=>sub {
	state $data= "x" x (4096*4096);
	my $size=4096*128;
	my $offset=0;#-$size;;
	rex_reply @_, HTTP_OK, undef, sub {
		return unless $_[0];

		my $d=substr($data, $offset, $size);	#Data to send
		$offset+=$size;				#update offset
		
		$_[0]->($d, $offset<length $data?__SUB__:undef);	#send substr
	};
});

$server->add_route("GET"=>"/array"=>()=>sub {
	rex_reply @_, HTTP_OK, undef, [qw<this is a set of data>];
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
