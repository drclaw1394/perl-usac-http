package uSAC::HTTP;
use strict;
use feature qw<say state refaliasing>;
use utf8;
use warnings;
use version; our $VERSION=version->declare("v0.1");
use Log::ger;
use Log::OK {
	lvl=>"info",
	opt=>"verbose",
};

use uSAC::HTTP::Server;
use uSAC::HTTP::Site;
use uSAC::HTTP::Static;
use uSAC::HTTP::Rex;
#use uSAC::HTTP::Middleware qw<dummy_mw log_simple>;
use uSAC::HTTP::Code ":constants";
use uSAC::HTTP::Header ":constants";
use uSAC::HTTP::Method ":constants";
#use enum qw<ROUTE REX CODE HEADER PAYLOAD CB>;

our $Site;
#use Exporter "import";
sub import {
	my $caller=caller;
	strict->import;
	warnings->import;
	feature->import(qw<say state refaliasing current_sub>);
	#feature->unimport(qw<indirect>);
	utf8->import;

	#say join ", ", @_;
	if(@_==1){
		#Anything sub with usac or rex prefix is rexported
		#Also http constants and headers are rexported
		#
		for(keys %uSAC::HTTP::){
			#print $_."\n";
			no strict "refs";
			if( /^usac_/ or /^rex_/ or  /^HTTP_/){
				*{$caller."::".$_}=\*{"uSAC::HTTP::".$_};
			}
			elsif(/Dir_Path/ or /File_Path/ or /Comp/ ){
				#print 'Symbol name: '.$_."\n";;
				s/\$//;
				my $name='*'.$caller."::".$_;
				*{$name}=\${'uSAC::HTTP::Site::'.$_};
			}
		}
	}
	if(@_==1 or grep /:constants/, @_){
		#Export contants
		my $i=0;
		for(qw<ROUTE REX CODE HEADER PAYLOAD CB>){
			no strict "refs";
			my $name='*'.$caller."::".$_;
			my $a=$i;
			*{$name}=sub {$a};#\${'uSAC::HTTP::'.$_};
			$i++;
		}
	}
}
1;
