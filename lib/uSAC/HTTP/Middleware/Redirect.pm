package uSAC::HTTP::Middleware::Redirect;

use uSAC::HTTP::Constants;
use uSAC::HTTP::Rex;
use Exporter "import";


our @EXPORT_OK=qw(
  uhm_redirect_set_other
  uhm_redirect_found
  uhm_redirect_temporary
  uhm_redirect_not_found
  uhm_redirect_internal
  uhm_error_not_found
);

our @EXPORT=@EXPORT_OK;

#Immediate redirects

sub uhm_redirect_see_other {
	my $url =pop;
	sub {
		$_[PAYLOAD]=$url;
		&rex_redirect_see_other;
	}

}

sub uhm_redirect_found{
	my $url =pop;
	sub {
		$_[PAYLOAD]=$url;
		&rex_redirect_found;
	}
}

sub uhm_redirect_temporary {
	my $url =pop;
	sub {
		$_[PAYLOAD]=$url;
		&rex_redirect_temporary;
	}
}

sub uhm_redirect_not_modified {
	my $url =pop;
	sub {
		$_[PAYLOAD]=$url;
		&rex_redirect_not_modified;
	}
}

sub uhm_redirect_internal {
	my $url =pop;
	sub {
		$_[PAYLOAD]=$url;
		&rex_redirect_internal;
	}

}

sub uhm_error_not_found {
	\&rex_error_not_found;
}

1;
