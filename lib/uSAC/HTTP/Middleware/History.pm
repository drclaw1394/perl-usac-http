package uSAC::HTTP::Middleware::History;

=head1 NAME 

  uSAC::HTTP::Middleware::History -  Stateful history management, with out cookies

=head1 DESCRIPTION

Using query parameters and post forms inconjuction with clients side, implements a history stack.
The user can traverse the user inteface stack independently in multiple windows. doesn't use cookies

Rendered via template

=cut
use v5.36;
use feature "try";

use constant::more qw<PUSH_CACHE=0  POP_CACHE NAME>;

use uSAC::IO;
use uSAC::HTTP::Rex;
use uSAC::HTTP::Constants;
use uSAC::HTTP::Header;
use uSAC::HTTP::Code;
use uSAC::HTTP::Route;
use uSAC::HTTP::Site;
#use MIME::Base64;
#use HTTP::State::Cookie qw<:encode :decode>;
#use Cpanel::JSON::XS;
#

use Import::These qw<uSAC::HTTP::Middleware:: Multipart Slurp Form State::Form>;



##    (Multipart -> Slurp -> Form Decode )->  State Form    -> History -> Template (render state)


use Export::These qw<uhm_history>;
# Manages a stack of page views over a sequence of requests.
# Encodes the stack in a url paramenter, instead of a cookie.
# The parameters is only sent for pages intended to render, not every resource, so much more targeted than cookie
# iF the user breaks the sequence of pages, it doesn't effect the site
#

my $random_name="stack";

sub create_stack {
  my $name=shift;
  [
    [CACHED()=>"", NAME()=>$name//$random_name],
    []
  ];
}





# TODO 
# need to check origin of referer
sub uhm_history{
  my %options=my @options=@_;
  my $state_name=$options{state_name};
  my $name=$options{name}//"viewstack";
  my $start_url=$options{start_url};
  (
    uhm_state_form(name=>$state_name, @options),
  [
    sub {
      my ($next)=@_;

      sub {
        if($_[OUT_HEADER]){
          #adump $STDERR, '=-=-==-=-=-=-=-=-=-=-=-=-==-=--=-=-=-=-=-=-==-';
          #adump $STDERR, "REX URI is", $_[REX][URI];

          #adump $STDERR, "REX PATH is", $_[REX][PATH];

          return &$next if $_[REX][PATH]=~m{\.};  # if it looks like a file... leave it alone

          for my $state ($_[REX][STATE]{$state_name}){

              
            # decode state if it need if
            #
            #$state//={decode_cookies $_[IN_HEADER]{HTTP_COOKIE()}};
           
            #adump $STDERR, "REX STATE in URL::STACK", $state;
            #adump $STDERR, "stack is expected in : $state_name";
            #adump $STDERR, " stack is at: {$state_name}{$name}";
            #adump $STDERR, " stack value is: ", $_[REX][STATE]{$state_name}{$name};



            my $stack=$_[REX][STATE]{$state_name}{$name}//=[];
            my $replace=delete $_[REX][STATE]{$state_name}{replace};

            my $referer=  $_[IN_HEADER]{HTTP_REFERER()};

            # TODO check the referer is of same origin. If not then reset the stack and redirect to start
            #

            #adump $STDERR, "Referer", $referer;

            use URI;
            my $url="URI"->new($referer);
            my $ref_path=$url->path;

            #adump $STDERR, "Referer path", $ref_path;


            # Strip out state variable
            my $rex_url=$_[REX][URI] =~ s/&{0,1}$state_name=\w*//r;

            ##adump $STDERR, "Request rex_url", $rex_url;
            #adump $STDERR, "org rex_url", $_[REX][URI];;
              
            my $current="URI"->new($_[REX][URI]);

            if($ref_path and $ref_path eq $current->path){
              #asay $STDERR, "---REF path and current resquest have equal paths";
              # referer is self... ie a post form submission with a redirect
              # do not modify the stack  if we have one
           

              # Could also be a manual reload. In this case reset stack
              @$stack=($_[REX][URI]) unless @$stack;



            }
            elsif($ref_path and $ref_path eq "URI"->new($stack->[-1])->path) {
              #asay $STDERR, "---REF path and top of stack equal paths";

              # Have a referer and top of stack is the referer.
              # GOING FORWARD OR BACKARD
              #
              #asay $STDERR, "Have a referer and is equal to top of stack";


                if("URI"->new($rex_url)->path eq "URI"->new($stack->[-2])->path){
                #if(undef){

                #asay $STDERR, "---current path and  second last stack are equal";
                # Current URL is actually the previous page so pop stack
                #
                #asay $STDERR, "--Backwards";

                # going backwards Remove state
                pop @$stack;
              }
              else {
                #asay $STDERR, "---current path and  second last stack are NOT equal";
                #asay $STDERR, "--Forward";
                

                # assume going forward, push current to stack, unless the the uri is the same as current stack top
                #

                # Replace the top of the stack if replace is set
                pop @$stack if $replace;
                #adump $STDERR, "Replacing top of stack going forward?", $replace;



                # Here we support the POST REDIRECT GET (PRG) pattern
                # Push to stack if NOT a post
                #
                # Also only push if the new url is different to the current top
                #
                if($_[REX][METHOD] ne "POST"){


                
                  push @$stack, $rex_url unless $rex_url eq $stack->[-1];
                }
              }
            }

            # Referer is not top of stack. So redirect to  home or  top of stack

            else{
              #asay $STDERR, "---REF path is OTHER";
              #asay $STDERR, $current->path, ("URI"->new($stack->[-1])->path);

              if($current->path eq "URI"->new($stack->[-1])->path) {
                # Current path is top of stack... We when back... do nothing.

              }
              else {

                # No stack or referer. Redirect to start, if we are not already there
                if($current->path ne $start_url){
                  #asay $STDERR, "URI is NOT equal to start. REX:",$current->path, "start:", $start_url;
                  $_[REX][REDIRECT]=$start_url;
                  $_[REX][QUERY]="";
                  return &rex_redirect_found;
                }
                @$stack=($_[REX][URI]);
              }
          }
          #asay $STDERR, "---RESULT OF STACK ON THIS PAGE---", $stack;
            &$next;
            # Now up to templates to use above url functions to render  links in html
          }

        }
        else {
          &$next;
        }
      }
    },

    # Short circuit as we don't modify
    sub {
      my ($next)=@_;
      sub {
            if($_[REX][METHOD] =~ /(?:POST)|(?:PUT)|(?:PATCH)/){

              #my $q="$state_name=$_[PAYLOAD][0][PART_CONTENT]{$state_name}";
               my $q="$state_name=".encode_html_state_from $_[REX][STATE], $state_name;
              #my $a=$_[REX][REDIRECT]=$_[REX][PATH]."?$q";
              $_[REX][QUERY]=join "&", $_[REX][QUERY]//(), $q;
              return &rex_redirect_found;
            }
            else {
              &$next;
            }
      }
    }

  ]
)
}







__END__

/my/inspection/?id=1&stack=[]
  
  urls to link to entity selection list. The stack

  /my/entities/?chooser=true&$stack=[currentURL]


ON the chooser page rendered

  urls to the previous page (inspections)  with results of selection
  peek the top of the stack to render previous url  and return value

  /my/inspection/?id=1&stack=[]&result=DATA


  for links to logo uploader, the current url is pushed to the state

  /my/logo/?id=1&stack=[currentURL, currentURL]
