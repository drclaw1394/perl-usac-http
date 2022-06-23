package uSAC::HTTP;
use strict;
use feature qw<say state refaliasing>;
use utf8;
use warnings;
use version; our $VERSION=version->declare("v0.1");
use uSAC::HTTP::Server;
use uSAC::HTTP::Site;
use uSAC::HTTP::Static;
use uSAC::HTTP::Rex;
#use uSAC::HTTP::Middleware qw<dummy_mw log_simple>;
use uSAC::HTTP::Code ":constants";
use uSAC::HTTP::Header ":constants";
use uSAC::HTTP::Method ":constants";

our $Site;
#use Exporter "import";
sub import {
	my $caller=caller;
	strict->import;
	warnings->import;
	feature->import(qw<say state refaliasing current_sub>);
	#feature->unimport(qw<indirect>);
	utf8->import;


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
1;
