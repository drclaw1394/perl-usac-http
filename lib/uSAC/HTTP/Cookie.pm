package uSAC::HTTP::Cookie;
use Exporter 'import';

BEGIN {
	our @names=qw<
		Undef
		Name
		Value
		Expires
		Max-Age
		Domain
		Path
		Secure
		HTTPOnly
	>;
	our @values= 0 .. @names-1;

	our %const_names=map { (("COOKIE_".uc $names[$_])=~tr/-'/_/r, $values[$_]) } 0..@names-1;
	#our @const_list=%const_names;
}

use feature qw<switch say>;
no warnings "experimental";

use constant \%const_names;

our %reverse; @reverse{@names}=@values;
$reverse{undef}=0;			#catching


our @EXPORT_OK= keys %const_names;
our %EXPORT_TAGS=(
	constants=> [keys %const_names]
);

#cookie 
sub new {
	my $package=shift//__PACKAGE__;
	my $self=bless [], $package;
	$self->[COOKIE_HTTPONLY]=undef;	#allocate storage

	$self->[COOKIE_NAME]=shift;
	$self->[COOKIE_VALUE]=shift;
	$self;
}

#Attribues can be set direclty
sub parse {
	my $input=shift;
	my $key;
	my $value;
	my @values;
	my $first=1;

	for(split ";", $input){
		($key,$value)=split "=";
		if($first){
			$first=0;
			($values[1],$values[2])= split "=";
		}
		else {
			tr/ //d;
			say ;
			($key,$value)= split "=";
			say "key $key, value $value";
			$values[$reverse{$key}]=$value//1;
		}

	}
	bless \@values, __PACKAGE__;
}

sub serialize {
	my $self=shift;
	my $cookie= "$self->[COOKIE_NAME]=$self->[COOKIE_VALUE]";			#Do value
	for my $index (COOKIE_EXPIRES, COOKIE_MAX_AGE, COOKIE_DOMAIN, COOKIE_PATH){	#Do Attributes
		given($self->[$index]){
			$cookie.="; $names[$index]=$_" when defined;			#Only defined attribues are added
		}
	}

	$cookie.="; Secure" if defined $self->[COOKIE_SECURE];				#Do flag attributes
	$cookie.="; HTTPOnly" if defined $self->[COOKIE_HTTPONLY];

	$cookie;
}

1;
