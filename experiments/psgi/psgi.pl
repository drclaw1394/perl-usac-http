use v5.36;
use EV;
use AnyEvent;
use Log::ger::Output 'Screen';
use Log::OK;

use Import::These qw<uSAC::HTTP:: Server ::Middleware:: Log PSGI>;

my $app3=sub {
  my $env=shift;
  sub {
    my $responder=shift;
    my $t; $t=AE::timer 1.0, 0, sub {
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

my $server;
$server=uSAC::HTTP::Server->new(listener=>"a=0.0.0.0,po=8081,t=stream");
$server->add_route("app3" =>uhm_psgi $app3);

use Plack::Builder;

my $app2=sub {

  [200,[],["app2"]];
};

builder {
  #enable "Plack::Middleware::AccessLog", format => "combined";
    $app2;
};

$server->add_route("app2" =>uhm_psgi $app2)
  ->add_route("app0" =>uhm_psgi(\"test.psgi"))
  ->add_route("app4" =>uhm_psgi $app4);

$server->process_cli_options
  ->run;
