use strict;
use warnings;
use feature ":all";

use Template::Vanilla;


my $cache=Template::Vanilla->new();

my $buffer="";
include "./experiments/html.plate",  $cache, \$buffer, qw< more arguments>;
say $buffer;
