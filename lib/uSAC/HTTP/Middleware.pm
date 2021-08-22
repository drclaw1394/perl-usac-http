package uSAC::HTTP::Middleware;
use strict;
use warnings;
use Exporter 'import';
use feature qw<refaliasing say switch state>;
no warnings "experimental";
no feature "indirect";
use Data::Dumper;
use uSAC::HTTP::Session;
use uSAC::HTTP::Rex;
use uSAC::HTTP::Cookie qw<:all>;
use uSAC::HTTP::Code qw<:constants>;

use IO::Compress::Gzip;
use Compress::Raw::Zlib;
use constant LF => "\015\012";

our @EXPORT_OK=qw<log_simple authenticate_simple make_chunked_writer make_chunked_deflate_writer>;
our @EXPORT=();
our %EXPORT_TAGS=(
	"all"=>[@EXPORT_OK]
);
use uSAC::HTTP::Middler;
#INCOMMING REX PROCESSING
#
#log to STDERR
sub log_simple {

	#No configuration used in this logger, so reuse the same sub for each call
	state $sub=sub {
		my $next=shift;	#This is the next mw in the chain
		say "making log";
		sub {
			#say STDERR Dumper $_[1];
			say STDERR "\n";
			say STDERR time;
			say STDERR " Original URI: $_[1][uSAC::HTTP::Rex::uri_]";
			say STDERR " Matcher:	   $_[0]";
			return &$next;		#alway call next. this is just loggin
		}
	};
	$sub;
}


sub authenticate_simple{
	my $next=shift;
	say "making authenticate with next: ", $next; 
	sub {
		#this sub input is line, and rex
		my $rex=$_[1];
		my $cookies=parse_cookie $rex->headers->{cookie};
		say "checking cookies";
		#check that the current ip address of the client is the same as previously set?
		unless($cookies->{test}){
			say "invalid test variable... return forbidden";
			rex_reply_simple @_, (HTTP_FORBIDDEN, undef, "Go away!");
			return;
		}

		return &$next;		#alway call next. this is just loggin
	}
}


#DEFAULT END POINT HANDLER
#


#TRANFER ENCODINGS OUTPUTS
#
#Takes input and makes chunks and writes to next
sub chunked {
	my $next=shift;
	say "making chunked with", $next; 
	my $scratch="";

	sub {
		#say "Calling chunked";
		my $cb=$_[1];
		unless(defined $_[0]){
			return $next->(undef,$cb);
		}
		\my $buf=\$_[0];	#input buffer
		#take the length of the input buffer 
		$scratch=sprintf("%02X".LF,length $buf);
		$scratch.=$buf.LF;
		#say "Scratch: ", $scratch;
		$next->($scratch,$cb);
	}
}
sub gzip {
	my $next=shift;
	say "making gzip with ", $next;
	my $scratch="";
	my $compressor;
	sub {

		my $cb=$_[1];
		unless(defined $_[0]){
			#reset
			$compressor->close if $compressor;
			return $next->(undef,$cb);
		}
		\my $buf=\$_[0];

		$scratch="";
		unless($compressor){
			#say "Creating new compressor";
			$scratch="";
			$compressor=IO::Compress::Gzip->new(\$scratch, "-Level"=>-1, Minimal=>1);
		}
		if(length $buf ==0){
			#say "End of data received";
			$compressor->close;
			$compressor=undef;
			$next->($scratch,sub {
					#pass on done to next
					$next->("",$cb);
			});
		}
		else{
			#say "data received";
			$compressor->syswrite($buf);
			if(length $scratch){
				#say "sending scratch";
				$next->($scratch,$cb);
			}
			else {
				#say "no new  data";
				#trigger upstream for more
				$cb->(1);
			}
		}

	}
}

sub deflate {
	my $next=shift;
	say "making deflate with ", $next;
	my $scratch="";
	my $compressor;
	my $status;
	$compressor=Compress::Raw::Zlib::Deflate->new(-AppendOutput=>1, -Level=>6);
	say $compressor;
	$scratch="";
	sub {
		my $cb=$_[1];
		unless(defined $_[0]){
			#reset
			#$compressor->close if $compressor;
			return $next->(undef,$cb);
		}

		\my $buf=\$_[0];


		if(length $buf ==0){
			#say "End of data received";
			$status=$compressor->flush($scratch);
			say "Status of flush: $status";
			say " scratch length: ", length $scratch;
			#$compressor=undef;
			$next->($scratch,sub {
					#pass on done to next
					$scratch="";
					$status=$compressor->deflateReset();
					say "Status of deflateReset: $status";
					$status == Z_OK or say "this isn;t good";
					$next->("",$cb);
			});
		}
		else{
			say "data received, ", length $buf;
			$status=$compressor->deflate($buf, $scratch);
			say "Status of deflat: $status";
			$status == Z_OK or say "this isn;t good";
			if(length $scratch){
				#say "sending scratch";
				$next->($scratch,$cb);
			}
			else {
				#say "no new  data";
				#trigger upstream for more
				$cb->(1);
			}
		}

	}
}
#returns a stack entry point which will write set of input data as a chunk to ouput
sub make_chunked_deflate_writer {
	my $session=shift;
	#create a chunked sub
	#and link to the writer of the session
	my ($entrypoint,$stack)=uSAC::HTTP::Middler->new()
	->register(\&uSAC::HTTP::Middleware::deflate)
	->register(\&uSAC::HTTP::Middleware::chunked)
	->link($session->[uSAC::HTTP::Session::write_]);	#this could be a normal socket writer, orssl type
	return $entrypoint;
}

#returns a stack entry point which will write set of input data as a chunk to ouput
sub make_chunked_writer {
	my $session=shift;
	#create a chunked sub
	#and link to the writer of the session
	my ($entrypoint,$stack)=uSAC::HTTP::Middler->new()
	->register(\&uSAC::HTTP::Middleware::chunked)
	->link($session->[uSAC::HTTP::Session::write_]);	#this could be a normal socket writer, orssl type
	return $entrypoint;
}

given(\%uSAC::HTTP::Session::make_writer_reg){
	#$_->{http1_1_static_writer}=\&make_static_file_writer;
	$_->{http1_1_chunked_writer}=\&make_chunked_writer;
	$_->{http1_1_chunked_deflate_writer}=\&make_chunked_deflate_writer;
}

1;
