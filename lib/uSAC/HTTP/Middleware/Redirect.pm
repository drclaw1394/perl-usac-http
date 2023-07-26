package uSAC::HTTP::Middleware::Redirect;

use uSAC::HTTP::Constants;
use uSAC::HTTP::Rex;


use Export::These qw(
  uhm_redirect_see_other
  uhm_redirect_found
  uhm_redirect_temporary
  uhm_redirect_permanent
  uhm_redirect_internal
  uhm_error_not_found
);


#Immediate redirects

=head3 uhm_redirect_see_other

  eg 
    usac_route "some_path"=>uhm_redirect_see_other "new_location";

Wrapper around rex_redirect_see_other to be used as innerware directly.
=cut
sub uhm_redirect_see_other {
	my $url =pop;
	sub {
		$_[PAYLOAD]=$url;
		&rex_redirect_see_other;
	}
}

=head3 uhm_redirect_found

  eg 
    usac_route "some_path"=>uhm_redirect_found "new_location";

Wrapper around rex_redirect_found to be used as innerware directly.
=cut
sub uhm_redirect_found{
	my $url =pop;
	sub {
		$_[PAYLOAD]=$url;
		&rex_redirect_found;
	}
}



=head3 uhm_redirect_temporary

  eg 
    usac_route "some_path"=>uhm_redirect_temporary "new_location";

Wrapper around rex_redirect_temporary to be used as innerware directly.
=cut
sub uhm_redirect_temporary {
	my $url =pop;
	sub {
		$_[PAYLOAD]=$url;
		&rex_redirect_temporary;
	}
}

=head3 uhm_redirect_permanent

  eg 
    usac_route "some_path"=>uhm_redirect_permanent "new_location";

Wrapper around rex_redirect_temporary to be used as innerware directly.
=cut
sub uhm_redirect_permanent {
	my $url =pop;
	sub {
		$_[PAYLOAD]=$url;
		&rex_redirect_permanent;
	}
}



=head3 uhm_redirect_not_modified

  eg 
    usac_route "some_path"=>uhm_redirect_not_modified;

Wrapper around rex_redirect_not_modified to be used as innerware directly.
=cut
sub uhm_redirect_not_modified {
  #my $url =pop;
	sub {
    #$_[PAYLOAD]=$url;
		&rex_redirect_not_modified;
	}
}



=head3 uhm_redirect_internal

  eg 
    usac_route "/some_path"=> uhm_redirect_internal "/new_path";
    
Wrapper around rex_redirect_internal to be used as innerware directly.
Effectivly makes a request appear to match another end point. 
=cut
sub uhm_redirect_internal {
	my $url =pop;
	sub {
		$_[PAYLOAD]=$url;
		&rex_redirect_internal;
	}
}



=head3 uhm_error_not_found

  eg 
    usac_route "some_"=> uhm_error_not_found;
    usac_catch_route uhm_error_not_found;
    
Wrapper around rex_error_not_found to be used as innerware directly.
=cut
sub uhm_error_not_found {
	\&rex_error_not_found;
}

1;
