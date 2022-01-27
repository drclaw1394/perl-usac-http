package uSAC::HTTP::Cookie;
#use strict;
#use warnings;
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
		SameSite
	>;
	our @values= 0 .. @names-1;

	my @same_site=qw<Lax Strict None>;
	my @pairs=
		(map { (("COOKIE_".uc $names[$_])=~tr/-'/_/r, $values[$_]) } 0..@names-1),	#elements
		(map {("SAME_SITE_".uc, $_)} @same_site)						#same site vals
	;						

	our %const_names=@pairs;
}


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

#Create a new cookie without package
#First 2 arguements are name=>value
#Remaining arguments are key=>value
#keys must be valled exported ones
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

###SERVER SIDE
#expires a list of cookies by name
#Creates a list of new cookes with the name set and expiry set to before current time
sub expire_cookies {
	my $package=__PACKAGE__;
	map {
		my $self=bless [], $package;
		$self->[COOKIE_HTTPONLY]=undef;	#allocate storage

		$self->[COOKIE_NAME]=$_;
		$self->[COOKIE_VALUE]="";
		$self->[COOKIE_EXPIRES]=time-3600;
		$self;
	} @_;
}

#used server side to render a set cookie value
sub serialize_set_cookie{
	my $self=shift;
	my $cookie= "$self->[COOKIE_NAME]=$self->[COOKIE_VALUE]";			#Do value
	for my $index (COOKIE_MAX_AGE, COOKIE_DOMAIN, COOKIE_PATH, COOKIE_SAMESITE){	#Do Attributes
		for($self->[$index]){
			$cookie.="; $names[$index]=$_" if defined;			#Only defined attribues are added
		}
	}
	
	for($self->[COOKIE_EXPIRES]){
		if(defined){
			my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) =gmtime $self->[COOKIE_EXPIRES];
			$cookie.="; Expires=$days[$wday], $mday $months[$mon] ".($year+1900) ." $hour:$min:$sec GMT";
		}
	}
	$cookie.="; Secure" if defined $self->[COOKIE_SECURE];				#Do flag attributes
	$cookie.="; HTTPOnly" if defined $self->[COOKIE_HTTPONLY];

	$cookie;
}

#Parse cookie string from client into key value pairs.
#Used server side on incoming request
sub parse_cookie {
	my %values;
	for(split ";", $_[0]=~tr/ //dr){
		($key,$value)= split "=";
		$values{$key}=$value;
	}
	\%values;
}


##CLIENT SIDE
#
#Parse the key value and attributes from a servers set-cookie header
#Used client side on incoming response
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
			#say "key $key, value $value";
			$values[$reverse{$key}]=$value//1;
		}

	}
	bless \@values, __PACKAGE__;
}



##Accessors methods
#
sub  name : lvalue { $_[0][COOKIE_NAME] }
sub  value : lvalue { $_[0][COOKIE_VALUE] }
sub  domain : lvalue{ $_[0][COOKIE_DOMAIN] }
sub  http_only: lvalue{ $_[0][COOKIE_HTTPONLY] }
sub  expires :lvalue{ $_[0][COOKIE_EXPIRES] }
sub  max_age :lvalue{ $_[0][COOKIE_MAX_AGE] }
sub  path :lvalue{ $_[0][COOKIE_PATH] }
sub  secure :lvalue{ $_[0][COOKIE_SECURE] }

1;
