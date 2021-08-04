package uSAC::HTTP::Cookie;
use Exporter 'import';

#Please refer to rfc6265 HTTP State Management Mechanism
#
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


our @EXPORT_OK= (parse_cookie, new_cookie, expire_cookies, keys %const_names);
our %EXPORT_TAGS=(
	constants=> [keys %const_names],
	all=>		[@EXPORT_OK]
);

my @months = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
my @days= qw(Sun Mon Tue Wed Thu Fri Sat);

#cookie 
sub new {
	my $package=shift//__PACKAGE__;
	my $self=bless [], $package;
	$self->[COOKIE_HTTPONLY]=undef;	#allocate storage

	$self->[COOKIE_NAME]=shift;
	$self->[COOKIE_VALUE]=shift;

	#remainder of values are key value pairs
	my $i=0;
	for(0..@_/2-1){
		$self->[$_[$i]]=$_[$i+1]; $i+=2;
	}

	$self;
}

sub new_cookie {
	my $package=__PACKAGE__;
	my $self=bless [], $package;
	$self->[COOKIE_HTTPONLY]=undef;	#allocate storage

	$self->[COOKIE_NAME]=shift;
	$self->[COOKIE_VALUE]=shift;

	#remainder of values are key value pairs
	my $i=0;
	for(0..@_/2-1){
		$self->[$_[$i]]=$_[$i+1]; $i+=2;
	}

	$self;

}
#expires a list of cookies by name
sub expire_cookies {
	my $package=__PACKAGE__;
	map {
		my $self=bless [], $package;
		$self->[COOKIE_HTTPONLY]=undef;	#allocate storage

		$self->[COOKIE_NAME]=$_;
		$self->[COOKIE_VALUE]="ddd";
		$self->[COOKIE_EXPIRES]=time-3600;
		$self;
	} @_;
}

#Parse cookie string from client into key value pairs.
sub parse_cookie {
	my %values;
	for(split ";", $_[0]=~tr/ //dr){
		($key,$value)= split "=";
		$values{$key}=$value;
	}
	\%values;
}



#Parse the key value and attributes from a servers set-cookie header
sub parse_set_cookie {
	my $key;
	my $value;
	my @values;
	my $first=1;

	for(split ";", $_[0]=~ tr/ //dr){
		($key,$value)=split "=";
		if($first){
			$first=0;
			($values[1],$values[2])= split "=";
		}
		else {
			($key,$value)= split "=";
			say "key $key, value $value";
			$values[$reverse{$key}]=$value//1;
		}

	}
	bless \@values, __PACKAGE__;
}

sub serialize_set_cookie{
	my $self=shift;
	my $cookie= "$self->[COOKIE_NAME]=$self->[COOKIE_VALUE]";			#Do value
	for my $index (COOKIE_MAX_AGE, COOKIE_DOMAIN, COOKIE_PATH){	#Do Attributes
		given($self->[$index]){
			$cookie.="; $names[$index]=$_" when defined;			#Only defined attribues are added
		}
	}
	
	given($self->[COOKIE_EXPIRES]){
		when(defined){
			my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) =gmtime $self->[COOKIE_EXPIRES];
			$cookie.="; Expires=$days[$wday], $mday $months[$mon] ".($year+1900) ." $hour:$min:$sec GMT";
		}
	}
	$cookie.="; Secure" if defined $self->[COOKIE_SECURE];				#Do flag attributes
	$cookie.="; HTTPOnly" if defined $self->[COOKIE_HTTPONLY];

	$cookie;
}
1;
