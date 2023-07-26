package uSAC::HTTP::Middleware::Log;
use strict;
use warnings;

use feature qw<refaliasing say state>;
no warnings "experimental";

#no feature "indirect";
#use uSAC::HTTP::Session;
use uSAC::HTTP::Code;
use uSAC::HTTP::Header;
use uSAC::HTTP::Rex;
use uSAC::HTTP::Constants;

use Time::HiRes qw<time>;


use Log::ger;
use Log::OK;

use Export::These qw<uhm_log>;


# ===========
# Log Simple - Log basic stats to STDERR
#
sub uhm_log {
	[&log_simple_in, &log_simple_out, undef];
}

sub log_simple_in {

	my %options=@_;

  my $dump_headers=$options{dump_headers};

  my $dumper;
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
            "Original matched URI: 	$_[IN_HEADER]{':path'}",
            "Site relative URI:	$_[IN_HEADER]{':path_stripped'}",
            "Matched for site:	".($_[ROUTE][1][ROUTE_SITE]->id//"n/a"),
            "Hit counter:		$_[ROUTE][1][ROUTE_COUNTER]"
          );

          if($dump_headers){
            push @out, "==Incomming Headers==","";
            require Data::Dumper;
            $dumper=Data::Dumper->new([$_[IN_HEADER]]);
            $dumper->Sortkeys(1);
            push @out, $dumper->Dump;
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
  my $dumper;

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
        $dumper=Data::Dumper->new([$_[OUT_HEADER]]);
        $dumper->Sortkeys(1);
        push @out, $dumper->Dump;
      }
      say STDERR join "\n", @out;

			&$outer_next;
		}
	};
}

1;
