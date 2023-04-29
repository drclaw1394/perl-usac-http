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

our @EXPORT_OK=qw< uhm_log >;

our @EXPORT=@EXPORT_OK;
our %EXPORT_TAGS=();

# ===========
# Log Simple - Log basic stats to STDERR
#
sub uhm_log {
	[&log_simple_in, &log_simple_out, uSAC::HTTP::Middleware::bypass]
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
          say STDERR "Host: 			$_[REX][host_]";
          say STDERR "Method:       $_[REX][method_]";
          say STDERR "Original matched URI: 	$_[REX][uri_raw_]";
          say STDERR "Site relative URI:	$_[REX][uri_stripped_]";
          say STDERR "Matched for site:	".($_[ROUTE][1][0]->id//"n/a");
          say STDERR "Hit counter:		$_[ROUTE][1][3]";
          say STDERR "Captures:\n".join "\n",$_[1][captures_]->@* if $dump_capture;
          if($dump_headers){
            say STDERR "Headers:\n" if $dump_headers;
            my $headers=$_[REX]->headers;
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
