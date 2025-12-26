use v5.36;


use Import::These qw<uSAC::HTTP:: Server Site>;
use uSAC::HTTP::Form;

use HTTP::State::Cookie ":all";
use Import::These qw<uSAC::HTTP::Middleware::
  Static Log Deflate Log
  Gzip Slurp ScriptWrap
  TemplatePlex2
  Redirect State
>;

my $delegate= require(path(\"delegate.pl"));


# Secrets are stored in an array per listener tag
# That means each listener group can be configured (ie multiple ports and interfaces)
# to use a set of secrets
$parent->add_secret("http://192.168.0.2:9090", [key=>"asdf"]);


# Protocols are stored in an array per listener tag.
# That means each listener group can be configured to use a particular protocol
#$server->add_protocol(

#$listener_db={
# listener_tag=>{       # Unique tag identifying this listener group
#   fds=>[fd],          # Array of file descriptors in this group
#   secrets=>{          # Secrets indentifying hosts, eg cert, key 
#       host=>{
#         cert=>.pem,
#         key=>.pem
#
#         }
#   },
#
#   protocol=>{         # Protocol names resolving to subs  or sub names
#     name=>sub...
#
#   }
# }
#}

my $site;
$parent
#->add_middleware(uhm_state)
#->add_middleware(uhm_log dump_headers=>1)
  ->add_site($site=uSAC::HTTP::Site->new(
    id=>"blog",
    delegate=>$delegate
  ));
  
#$site->add_route(POST=>"login")
  #->add_route("login")
  #->add_route("logout")
  #->add_route("public")
  #->add_route("home")

  #->set_error_page(404=>\"not_found");
  #->add_route(""=>sub { $_[PAYLOAD]="asdfasd default"})
  #
$parent->process_cli_options
