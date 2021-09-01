use strict;
use warnings;
use feature qw<state say>;

use uSAC::HTTP;
use uSAC::HTTP::Code qw<:constants>;
use uSAC::HTTP::Rex;
use uSAC::HTTP::Server;
use uSAC::HTTP::Server::WS;
use feature "current_sub";

$uSAC::HTTP::Session::make_reader_reg{"websocket"}=\&make_websocket_server_reader;
$uSAC::HTTP::Session::make_writer_reg{"websocket"}=\&make_websocket_server_writer;

my $server=uSAC::HTTP::Server->new(
	host=>"0.0.0.0",
	port=>8081,
	#cb=>sub{}
);

site_route $server =>'GET'=>"/\$"=>sub {
	local $/=undef;
	state $data;
	$data=<DATA> unless $data;	#TODO: bug. <> operator not working with state
	#say "WILL SEND DATA: ", $data;
	rex_reply_simple(@_, HTTP_OK, undef, $data);
	return;
};

site_route $server => GET=>"/ws"=>sub {
	say "Websocket upgrade";
	my $ws;
	my $writer;
	upgrade_to_websocket @_	,sub {
		$ws=$_[0];
		$ws->on_message(sub {
			say "GOT message: $_[0]" if $_[0];
			$ws->write_text("return data");
		});
		$ws->on_error(sub {
			say "GOT error$_[0]";
		});
		$ws->on_close(sub {
			say "GOT close $_[0]";
		});
		say "GOT WEBSOCKET ", $_[0];

	};
};

site_route $server=>"GET"=>"/large"=>()=>sub {
	state $data= "x"x(4096*4096);
	rex_reply_simple @_,HTTP_OK,undef,$data;
};
site_route $server=>"GET"=>"/chunks"=>()=>sub {
	state $data= "x"x(4096*4096);
	my $size=4096*1024;
	my $offset=-$size;;
	rex_reply @_, HTTP_OK, undef, sub {

		$offset==length $data and return;			#break out when sent all
		$_[0]->(substr($data, $offset+=$size, $size),__SUB__);	#send substr
	};
};

site_route $server=>"GET"=>"/array"=>()=>sub {
	rex_reply @_, HTTP_OK, undef, [qw<this is a set of data>];
};

$server->run;

__DATA__
<html>
	<head>
		<title>WS test </title>
	</head>
	<body>
		<script >
			var ws=new WebSocket("ws://localhost:8081/ws","chat");

			ws.onopen=function(event){
				console.log("websocket open");
				ws.send("Hello");
			};

			ws.onmessage= function(msg){
				console.log("websocket message",msg);
				};
			ws.onerror= function(msg){
				console.log("websocket error",msg);
			};
			setInterval(function(){
				ws.send("from client");
			},1000);
		</script>

	</body>
<html>
