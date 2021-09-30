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
	my $renderer=sub {@_};#$_[2];

	my @innerware;
	my @outerware;
	my @mw;

	for my $i (reverse 0..@middleware-1){
		my $maker=$middleware[$i];
		my $innerware_next=($i==@middleware-1)?$dispatcher:$innerware[$i+1];	
		my $outerware_next=($i==@middleware-1)?$renderer:$outerware[$i+1];
		
		#my $next_target=($i==@middleware-1)?$dispatcher:$mw[$i+1];

		($innerware[$i],$outerware[$i])=$maker->($innerware_next, $outerware_next);
		#$mw[$i]=$maker->($next_target,$dispatcher);	#call with next and last
	}

	@innerware?($innerware[0],$outerware[0]):($dispatcher,$renderer);
	#return the entry to the stack and the ref to the list
	#(@middleware?$mw[0]:$dispatcher,\@mw);
	
}


1;
