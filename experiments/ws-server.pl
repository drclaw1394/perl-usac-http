use Import::These qw<uSAC::HTTP:: Server ::Middleware:: Log Websocket>;

my %clients;

my $server=uSAC::HTTP::Server->new(listen=>"f=INET\$,po=9090,s=stream");

$server->add_middleware(uhm_log);

$server->add_route('GET'
  =>'$'
  =>sub {
    local $/=undef; state $data; $data=<DATA> unless $data;	
    #TODO: bug. <> operator not working with state

    $_[PAYLOAD]=$data;	
  }
);

$server->add_route('GET'
  =>'ws$'
  => uhm_websocket()
  =>sub{
		my ($matcher, $rex, $in_headers, $headers, $ws)=@_;
		asay $STDERR, " IN usac websocket  callback: ",join ", ", @_;
		my $timer;
    $ws->on_open=sub {
      $clients{$_[0]}=$_[0];
      $timer=timer 0, 1, sub {
      asay $STDERR, "TIMER IS: $timer";
       my $string="hello";
       asay $STDERR, "Sending $string";
        $ws->send_text_message($string, sub {
            asay $STDERR, "CALLBACK";
          });
      };
    };

		$ws->on_message=sub {
				asay $STDERR, "GOT message: $_[1]";
				while(my($id, $client)=each  %clients){
					$client->send_text_message("hello") unless $client==$_[0];
				}
			};

		$ws->on_error=sub {
				asay $STDERR, "GOT error$_[0]";
			};

		$ws->on_close=sub {
				asay $STDERR, "GOT close";
        #undef $timer;
        asay $STDERR, "CLOSE TIMER: $timer";
        $timer and timer_cancel $timer;
			};
      undef; #Needed to prevent calling of next
	}
);


$server->process_cli_options(@ARGV);
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

