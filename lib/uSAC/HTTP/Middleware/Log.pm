package uSAC::HTTP::Middleware::Log;
use strict;
use warnings;
use Exporter 'import';
use feature qw<refaliasing say state>;
no warnings "experimental";

#no feature "indirect";
#use uSAC::HTTP::Session;
use uSAC::HTTP::Code qw<:constants>;
use uSAC::HTTP::Header qw<:constants>;
use uSAC::HTTP::Rex;
use uSAC::HTTP::Constants;

use Time::HiRes qw<time>;


use Log::ger;
use Log::OK;

our @EXPORT_OK=qw<
	log_simple
	authenticate_simple
	state_simple
>;
our @EXPORT=();
our %EXPORT_TAGS=(
	"all"=>[@EXPORT_OK]
);

# ===========
# Log Simple - Log basic stats to STDERR
#
sub log_simple {
	[&log_simple_in, &log_simple_out]
}

sub log_simple_in {
  require Data::Dumper;
	my %options=@_;

  my $dump_headers=$options{dump_headers};

  my $dump_capture=$options{dump_captures};
  my $sort_headers=$options{sort};
	#Header processing sub
	sub {
		my $inner_next=shift;	#This is the next mw in the chain
		sub {

      return &$inner_next unless $_[CODE] and $_[HEADER];
			my $time=time;

      package uSAC::HTTP::Rex {
          say STDERR "\n<<<---";
          say STDERR "Arraval initial time:		$time";
          say STDERR "Host: 			$_[1][host_]";
          say STDERR "Method:       $_[1][method_]";
          say STDERR "Original matched URI: 	$_[1][uri_raw_]";
          say STDERR "Site relative URI:	$_[1][uri_stripped_]";
          say STDERR "Matched for site:	".($_[0][1][0]->id//"n/a");
          say STDERR "Hit counter:		$_[0][1][4]";
          say STDERR "Captures:\n".join "\n",$_[1][captures_]->@* if $dump_capture;
          if($dump_headers){
            say STDERR "Headers:\n" if $dump_headers;
            my $headers=$_[1]->headers;
            my $out="";
            for my($k, $v)(%$headers){
              $out.="$k: $v\n"; 
            }
            say STDERR $out;
            #say STDERR Data::Dumper::Dumper $_[1]->headers if $dump_headers;
          }
			}
			&$inner_next;		#alway call next. this is just logging
		}
	};
	
	#Body processing sub
	
	#Return as a array [$header, $body]
}

sub log_simple_out {
	#header processing sub
	sub {
		my $outer_next=shift;
		sub {
			#matcher, rex, code, header, body, cb, arg
      return &$outer_next unless $_[CODE] and $_[HEADER];

      say STDERR "\n--->>>";
      say STDERR "Depature time:		".time;

			&$outer_next;
		}
	};

	#Body processing sub
	
	#Return as a array [$header, $body]
}
1;
