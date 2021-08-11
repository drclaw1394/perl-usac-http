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

use IO::Compress::Gzip;
use constant LF => "\015\012";

our @EXPORT_OK=qw<log_simple authenticate_simple default_handler make_chunked_writer make_chunked_gzip_writer>;
our @EXPORT=();
our %EXPORT_TAGS=(
	"all"=>[@EXPORT_OK]
);
use uSAC::HTTP::Middler;
#INCOMMING REX PROCESSING
#
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


#DEFAULT END POINT HANDLER
#
sub default_handler {
		my ($line,$rex)=@_;
		say "DEFAULT: $line";
		push @_, (HTTP_NOT_FOUND,undef,"Go away");
		&rex_reply_simple;#h $rex, ;
		return 1;
}


#TRANFER ENCODINGS OUTPUTS
#
#Takes input and makes chunks and writes to next
sub chunked {
	my $next=shift;
	#my $last=shift;
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
#returns a stack entry point which will write set of input data as a chunk to ouput
sub make_chunked_gzip_writer {
	my $session=shift;
	#create a chunked sub
	#and link to the writer of the session
	my ($entrypoint,$stack)=uSAC::HTTP::Middler->new()
	->register(\&uSAC::HTTP::Middleware::gzip)
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

1;
