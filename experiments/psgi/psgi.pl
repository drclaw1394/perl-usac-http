use uSAC::HTTP;
use uSAC::HTTP::PSGI;
use AnyEvent;

my $app=sub {
	my $env=shift;
	#say "App";
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
my $server;$server=usac_server {
	usac_listen "0.0.0.0:8081";
	usac_route "/app1"=>usac_to_psgi $app;
	usac_route "/app2"=>usac_to_psgi $app2;
	usac_route "/app3"=>usac_to_psgi $app3;

};
$server->run;
