#!/usr/bin/env perl
use v5.36;
#
use EV;
use AnyEvent;

use Log::ger::Output 'Screen';
use Log::OK {opt=>"verbose"};

use uSAC::HTTP::Server;
use uSAC::HTTP::Site;
use uSAC::Util qw<path>;

use Import::These qw<uSAC::HTTP::Middleware::
  Static Log Deflate Log
  Gzip Slurp ScriptWrap
  Redirect State
>;


my $server=uSAC::HTTP::Server->new(
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


my $delegate= require(path(\"delegate.pl"));
  print $delegate;
  print "\n";

$server
->add_site(uSAC::HTTP::Site->new(
    id=>"blog",
    delegate=>$delegate
  )
  ->add_route(POST=>"/login")
  ->add_route("/login")
  ->add_route("/logout")
  ->add_route("/public")
  ->add_route("/home")
  ->add_route("/getme/($Comp)"
    =>sub {
      $_[PAYLOAD]=join ", ", $_[IN_HEADER]{":captures"}->@*;
      1;
    }
  )
  ->add_route("/redirect"
    =>sub {
      $_[OUT_HEADER]{":status"}=301;
      $_[OUT_HEADER]{HTTP_LOCATION()}="http://localhost:8084/static/hot.txt";
    }
  )
  
  ->add_route('/static/hot.txt$'
    => uhm_static_file(
      #headers=>{"transfer-encoding"=>"chunked"},
      \"static/hot.txt")
  )

  ->add_route('/static'       
    => uhm_static_root(indexes=>["index.html"], list_dir=>undef, \"static")
    => uhm_static_root( \"admin/static")
  )
  #->add_route('/admin/static' => uhm_static_root)


  ->set_error_page(404=>\"not_found")
  #->add_route(""=>sub { $_[PAYLOAD]="asdfasd default"})
)
->parse_cli_options
->run;
