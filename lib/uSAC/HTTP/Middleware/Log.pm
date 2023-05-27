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

our @EXPORT_OK=qw<uhm_log>;

our @EXPORT=@EXPORT_OK;
our %EXPORT_TAGS=();

# ===========
# Log Simple - Log basic stats to STDERR
#
sub uhm_log {
	[&log_simple_in, &log_simple_out, uSAC::HTTP::Middleware::bypass]
}

sub log_simple_in {

	my %options=@_;

  my $dump_headers=$options{dump_headers};


  my $dump_capture=$options{dump_captures};

	#Header processing sub
	sub {
		my $inner_next=shift;	#This is the next mw in the chain
		sub {

      return &$inner_next unless $_[OUT_HEADER];
			my $time=time;

      package uSAC::HTTP::Rex {
          my @out=(
            "<<<---",
            "Arraval initial time:		$time",
            "Original matched URI: 	$_[REX][uri_raw_]",
            "Site relative URI:	$_[REX][uri_stripped_]",
            "Matched for site:	".($_[ROUTE][1][ROUTE_SITE]->id//"n/a"),
            "Hit counter:		$_[ROUTE][1][ROUTE_COUNTER]"
          );

          if($dump_headers){
            push @out, "==Incomming Headers==","";
            require Data::Dumper;
            push @out, Data::Dumper::Dumper $_[IN_HEADER];
          }
          push @out, "";
          say STDERR join "\n", @out;
			}
			&$inner_next;		#alway call next. this is just logging
		}
	};
}

sub log_simple_out {
	#header processing sub
  my %options=@_;
  my $dump_headers=$options{dump_headers};
	sub {
		my $outer_next=shift;
		sub {
			#matcher, rex, code, header, body, cb, arg
      return &$outer_next unless $_[OUT_HEADER];
      my @out;
      push @out, "Depature time:		".time;
      if($dump_headers){
        push @out, "==Outgoing Headers==","";
        require Data::Dumper;
        push @out, Data::Dumper::Dumper $_[OUT_HEADER];
      }
      say STDERR join "\n", @out;

			&$outer_next;
		}
	};
}
1;
