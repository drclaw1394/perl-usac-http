package uSAC::HTTP::Middleware;
use strict;
use warnings;
use Exporter 'import';
use feature "say";
use feature "refaliasing";
no warnings "experimental";
no feature "indirect";

use uSAC::HTTP::Rex;
use uSAC::HTTP::Cookie qw<:all>;
use uSAC::HTTP::Code qw<:constants>;

our @EXPORT_OK=qw<log_simple authenticate_simple default_handler>;
our @EXPORT=();
our %EXPORT_TAGS=(
	"all"=>[@EXPORT_OK]
);

#log to STDERR
sub log_simple {
	my $next=shift;	#This is the next mw in the chain
	my $last=shift;	#The last/target. for bypassing
	say "making log";
	sub {
		say STDERR time,": Request: $_[0]";
		return &$next;		#alway call next. this is just loggin
	}
}

sub authenticate_simple{
	my $next=shift;
	my $last=shift;
	say "making authenticate with next: ", $next; 
	sub {
		#this sub input is line, and rex
		my $rex=$_[1];
		my $cookies=parse_cookie $rex->headers->{cookie};
		say "checking cookies";
		#check that the current ip address of the client is the same as previously set?
		unless($cookies->{test}){
			say "invalid test variable... return forbidden";
			push @_, (HTTP_FORBIDDEN, undef, "Go away!");
			&rex_reply_simple;
			return;
		}

		return &$next;		#alway call next. this is just loggin
	}
}
sub default_handler {
		my ($line,$rex)=@_;
		say "DEFAULT: $line";
		push @_, (HTTP_NOT_FOUND,undef,"Go away");
		&rex_reply_simple;#h $rex, ;
		return 1;
}
1;
