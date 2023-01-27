use EV;
use AnyEvent;

use uSAC::HTTP;
use uSAC::HTTP::Middleware::PSGI;

use Log::ger::Output 'Screen';



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

my $server; $server=usac_server {
  usac_id "asdf";
	usac_listen "a=0.0.0.0,po=8081,t=stream";

        ################################################################################
        # usac_include root=>usac_dirname, "enabled";                                  #
        # #       usac_route "/app1"=>usac_to_psgi keep_alive=>1, $app;                #

  usac_route "/app3"=>psgi $app3;                                      
	usac_route "app0"=>psgi root=>usac_dirname, "test.psgi";
  usac_route "/app4"=>psgi keep_alive=>1, $app4;

        # usac_route "/app5"=>chunked()=>sub {                                         #
        #         rex_write @_, 200, [HTTP_CONTENT_TYPE, "text/plain"], "Hello there"; #
        # };                                                                           #
        ################################################################################
  usac_run;
};

