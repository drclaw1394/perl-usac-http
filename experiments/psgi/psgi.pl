use uSAC::HTTP;
use uSAC::HTTP::PSGI;
use AnyEvent;

my $app=sub {
	my $env=shift;
	state $c=0;

	#say "App". $c++;

	return [200,[],["content"]];
};
my $app2=sub {
	my $env=shift;
	#say "App2";
	my $res=open my $fh, "<", usac_path root=>usac_dirname, "test.txt";
	say $! unless $res;
	return [200, [], $fh];
};

my $app3=sub {
	my $env=shift;
	sub {
		my $responder=shift;
		my $t; $t=AE::timer 0.1,0,sub {
			$t=undef;
			$responder->([200,[],["delayed"]]);
		};
	}
};
my $app4=sub {
	my $env=shift;
	state $c=0;
	sub {
		my $responder=shift;
		my $w=$responder->([200,[]]);
		#say "App4 ".$c++;

		$w->write("Hello there how are you");
		$w->close;
	}
};
my $server;$server=usac_server {
	usac_listen "0.0.0.0:8081";
	usac_route "/app1"=>usac_to_psgi $app;
	usac_route "/app2"=>usac_to_psgi $app2;
	usac_route "/app3"=>usac_to_psgi $app3;
	usac_route "/app4"=>usac_to_psgi keep_alive=>1, $app4;
	usac_route "/app5"=>sub {
		rex_reply @_, 200, [], "Hello there";
	};

};
$server->run;
