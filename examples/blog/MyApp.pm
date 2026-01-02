package MyApp;
use uSAC::HTTP;
use Data::Dumper;
use uSAC::HTTP::Middleware qw<log_simple>;
use uSAC::HTTP::State::JSON qw<state_json>;

my @middle=state_json;

1;
