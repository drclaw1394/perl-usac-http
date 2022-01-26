package uSAC::HTTP::Middler;
use feature "refaliasing";
no warnings "experimental";
use feature qw<say switch>;

#simple middleware support


sub new {
	#simply an array...	
	bless [],__PACKAGE__;
}

#register sub refs to middleware makers
sub register {
	\my @middleware=$_[0];	#self
	my $sub=$_[1];
	push @middleware,$sub;
	return $_[0]; #allow chaining
}

#link the middlewares to each other (via next lexical)
#If no middlewares are present, the dispatcher is returned directly
#id no middleware overhead
#
sub link1 {
	\my @middleware=$_[0];	#self;

	my $dispatcher=$_[1];
	#link middle 
	#\my @mw=$_[1];	#actuall mw array

	#undef $_ for(@mw);		#destroy previous mw subs
	my @mw;

	for my $i (reverse 0..@middleware-1){
		my $maker=$middleware[$i];
		
		my $next_target=($i==@middleware-1)?$dispatcher:$mw[$i+1];

		$mw[$i]=$maker->($next_target,$dispatcher);	#call with next and last
	}

	#return the entry to the stack and the ref to the list
	
	(@middleware?$mw[0]:$dispatcher,\@mw);
	
}

sub link {
	\my @middleware=$_[0];	#self;

	my $dispatcher=$_[1];

	my @mw;

	for my $i (reverse 0..@middleware-1){
		my $maker=$middleware[$i];
		my $next=($i==@middleware-1)?$dispatcher:$mw[$i+1];	
		

		$mw[$i]=$maker->($next);
		#$mw[$i]=$maker->($next_target,$dispatcher);	#call with next and last
	}

	@middleware?$mw[0]:$dispatcher;
}


1;
