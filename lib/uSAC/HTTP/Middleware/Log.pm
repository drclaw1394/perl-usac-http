package uSAC::HTTP::Middleware::Log;
use strict;
use warnings;

use feature qw<refaliasing state>;
no warnings "experimental";

use Import::These qw<uSAC::HTTP:: Code Header Rex Route Constants>;

use Time::HiRes qw<time>;


use uSAC::Log; 
use Log::OK;

use Export::These qw<uhm_log>;



# ===========
# Log Simple - Log basic stats to STDERR
#
sub uhm_log {
  # Preprocess common config options
  my %options=@_;
  if($options{color}){
    my $res=require Data::Dump::Color;
    if($res){
      $options{dd}=\&Data::Dump::Color::dump;
    }
    else {
      Log::OK::WARN and log_warn "Please install Data::Dump::Color for colored log ouput";
    }
  }
  else {
    require Data::Dump;
      $options{dd}=\&Data::Dump::dump;
  }

	[log_simple_in(%options), log_simple_out(%options), undef];
}

sub log_simple_in {

	my %options=@_;
  my $dd=$options{dd};

  my $dump_headers=$options{dump_headers};

  my $dumper;
  my $dump_capture=$options{dump_captures};

	#Header processing sub
	sub {
		my $inner_next=shift;	#This is the next mw in the chain
		sub {

      if($_[OUT_HEADER]){
        my $time=time;

        my @out=(
          "<<<---",
          "Arraval initial time:		$time",
          "Original matched URI: 	$_[REX][PATH]",
          #"Site relative URI:	$_[IN_HEADER]{':path_stripped'}",
          "Matched for site:	".($_[ROUTE][1][ROUTE_SITE]->id//"n/a"),
          "Hit counter:		$_[ROUTE][1][ROUTE_COUNTER]"
        );

        if($dump_headers){
          push @out, "==Incomming Headers==","";
          push @out, $dd->($_[IN_HEADER]);
        }

        push @out, "";
        Log::OK::INFO and log_info join "\n", @out;
      }
			&$inner_next;		#alway call next. this is just logging
		}
	};
}

sub log_simple_out {
	#header processing sub
  my %options=@_;
  my $dump_headers=$options{dump_headers};
  my $dd=$options{dd};

	sub {
		my $outer_next=shift;
		sub {
			#matcher, rex, code, header, body, cb, arg
      if($_[OUT_HEADER]){
        my @out;
        push @out, "Depature time:		".time;
        if($dump_headers){
          push @out, "==Outgoing Headers==","";
          push @out, $dd->($_[OUT_HEADER]);
        }
        push @out, "--->>>";
        Log::OK::INFO and log_info join "\n", @out;
      }

			&$outer_next;
		}
	};
}

1;
