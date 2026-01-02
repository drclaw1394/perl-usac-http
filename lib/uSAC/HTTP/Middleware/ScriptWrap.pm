package uSAC::HTTP::Middleware::ScriptWrap;
use uSAC::HTTP::Header;
use uSAC::HTTP::Constants;


use Export::These qw(uhm_script_wrap);


sub uhm_script_wrap {

      [ undef,
         sub {
           my $next=shift;
           sub {
              if($_[OUT_HEADER]){
                $_[PAYLOAD]=qq|
                  let ss=document.currentScript;
                  let pp=ss.parentElement;
                  pp.removeChild(ss);
                  pp.innerHTML=`|.
                $_[PAYLOAD];
                # Make sure it will be chunked
                delete $_[OUT_HEADER]{HTTP_CONTENT_LENGTH()};
              }

              unless($_[CB]){
                $_[PAYLOAD].=qq|`;|;
              }
              &$next;
            }
        },
       undef
     ]
};
1;
