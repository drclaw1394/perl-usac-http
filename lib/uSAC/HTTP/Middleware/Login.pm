use v5.36;

package uSAC::HTTP::Middleware::Login;

# Middleware / site to help provide user login in a reusable way.  What does it
# do?  - Sets a request/form id to limit brute force attack each GET of login
# page genreate a new id
#
#   - Set



use Export::These qw<uhm_login>;


sub uhm_login {

  
  # Create a site
  my $site=uSAC::HTTP::Site->new;


  # Need to add routes for
  #
  #   GET login    -- url to redirect to
  #   POST login
  #   GET logout   -- url to redirect to
  #   POST logout
  #



  my %options=@_;

  # Options include the url to redirect 

  my $inner=sub {
    my $next=shift;



    sub {

    };
  };

  my $outer=sub {
  };

  my $error=undef;

  [$inner, $outer, $error];
}

1;
