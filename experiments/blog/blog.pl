#!/usr/bin/env perl
use v5.36;
#
#use EV;
use AnyEvent;

use Log::ger::Output 'Screen';
use Log::OK {opt=>"verbose"};

use Import::These qw<uSAC::HTTP:: Server Site>;
#use uSAC::HTTP::Server;
#use uSAC::HTTP::Site;
use uSAC::Util qw<path>;
use uSAC::HTTP::Form;

use HTTP::State::Cookie ":all";
use Import::These qw<uSAC::HTTP::Middleware::
  Static Log Deflate Log
  Gzip Slurp ScriptWrap
  TemplatePlex2
  Redirect State
>;

my $delegate= require(path(\"delegate.pl"));

my $server=uSAC::HTTP::Server->new(
  delegate=>$delegate,
  sub_product=>"Testing",
  listen=> {
    address=>"::",
    interface=>["en"],
    port=>[8084],
    family=>["AF_INET6"],
    type=>"SOCK_STREAM",
    data=> {
            hosts=>"dfs"
    }
  },
  workers=>0
);



my $site;
$server
->add_middleware(uhm_state)
  ->add_middleware(uhm_log dump_headers=>1)
  ->add_site($site=uSAC::HTTP::Site->new(
    id=>"blog",
    delegate=>$delegate
  ));
  
  $site->add_route(POST=>"login")
  ->add_route("login")
  ->add_route("logout")
  ->add_route("public")
  ->add_route("home")
  ->add_route(qr|getme/(($Comp)/)*($Comp)|n
    =>sub {
      $_[PAYLOAD]=join ", ", $_[IN_HEADER]{":captures"}->@*;
      1;
    }
  )
  ->add_route("delay", 
    [
      sub {
        my $next=shift;
        sub{
          use Time::HiRes "time";
          state $counter=0;
          state $prev_counter=0;
          state $timer=uSAC::IO::timer 0, 2, sub {
            
            say "Rate = @{[($counter-$prev_counter)/(2)]}";
            $prev_counter=$counter;
          };


          $counter++;
          ##############################
          # my @msg=@_;                #
          # uSAC::IO::timer 2,0, sub { #
          #     $msg[PAYLOAD]=time;    #
          #     $next->(@msg);         #
          # };                         #
          ##############################
          
          $_[PAYLOAD]=time;

          if($_[REX][STATE]{key}){

          }

          \my @sc=$_[OUT_HEADER]{HTTP_SET_COOKIE()}//[];
          
          push @sc, cookie_struct "asdfasd"=>"asdf";
          

          #push $_[OH]{HTTP_SET_COOKIE()}->@*, 
          push $_[OUT_HEADER]{HTTP_SET_COOKIE()}->@*, cookie_struct "test1", "value1";

          #$_[OUT_HEADER]{HTTP_CONTENT_LENGTH()}=length $_[PAYLOAD];
          &$next;
      }
    }
  ] 
)
  ->add_route("redirect"
    =>sub {
      $_[REX][STATUS]=301;
      $_[OUT_HEADER]{HTTP_LOCATION()}="http://localhost:8084/static/hot.txt";
    }
  )

  ->add_route('static/hot.txt$'
    => uhm_static_file(
      #headers=>{"transfer-encoding"=>"chunked"},
      \"static/hot.txt")
  )

  ->add_route('static'
    => uhm_static_root(
    #index=>["index.html"],
      list_dir=>1,
      roots=> [\"static", \"admin/static"],
      template=>qr/\.plex\./
    )
    => uhm_template_plex2

  )

  ->add_route($Any_Method, "");

  #->set_error_page(404=>\"not_found");
  #->add_route(""=>sub { $_[PAYLOAD]="asdfasd default"})
$server->process_cli_options
->run;
