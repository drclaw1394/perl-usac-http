use feature "say";
use strict;
use warnings;
package uSAC::HTTP::Constants;

use Exporter "import";

sub import {
	my $caller=caller;
	my $i=0;
	for(qw<ROUTE REX CODE HEADER PAYLOAD CB>){
		no strict "refs";
		my $name='*'.$caller."::".$_;
		my $a=$i;
		*{$name}=sub {$a};#\${'uSAC::HTTP::'.$_};
		$i++;
	}

}
1;
