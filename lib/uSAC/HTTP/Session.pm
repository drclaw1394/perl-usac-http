use Object::Pad;
package uSAC::HTTP::Session;
class uSAC::HTTP::Session;
use feature qw<say state refaliasing>;
no warnings "experimental";
use Log::ger;
use Log::OK;

use Scalar::Util 'openhandle','refaddr', 'weaken';
use Devel::Peek qw<SvREFCNT>;

use uSAC::IO::SReader;
use uSAC::IO::SWriter;
use Data::Dumper;


#require uSAC::HTTP::Server;
use EV;
use AnyEvent;
#use uSAC::HTTP::Server;

use Errno qw(EAGAIN EINTR);

use constant MAX_READ_SIZE => 128 * 1024;

field $_id;
field $_fh;
field $_sessions;
field @_zombies;
field $_server;
field $_scheme;
field $_time;
field $_closeme;
field $_rw;
field $_ww;
field $_wcb;
field $_left;
field $_read;
field $_write;
field $_request_count;
field @_read_stack;
field @_write_stack;
field $_current_reader;
field $_read_cache;
field $_writer_cached;
field $_rex;
field $_dropper;
field $_write_queue;
field $_sr;
field $_sw;
field $_in_progress;
field $_on_body;

our $Date;		#Date string for http
our $Time;		#seconds from epoch

sub _make_reader;
sub drop;


method init {
	
        $_time=$Time; 

	#$self->[read_stack_]=[];
	#$self->[reader_cache_]={};

	#$self->[write_stack_]=[];
	#
	#my $server=$self->[server_];
	#my $sessions=$self->[sessions_];
	#my $zombies=$self->[zombies_];
	#\my $fh=\$self->[fh_];
	#\my $id=\$self->[id_];
	#\my $closeme=\$self->[closeme_];

	#make reader
	$_sr=uSAC::IO::SReader->sreader(rfh=>$_fh);
	$_sr->max_read_size=4096*16;
	#$sr->on_read=\$self->[read_];
	($_sr->on_eof = sub {$_closeme=1; $_dropper->()});
	($_sr->on_error=$_sr->on_eof);
	$_sr->timing(\$_time, \$Time);
	#$self->[sr_]=$sr;


	$_sr->start;#uSAC::IO::SReader::start $sr;
	#$sr->start;

	#make writer
	$_sw=uSAC::IO::SWriter->swriter(wfh=>$_fh);

	#Takes an a bool argument: keepalive
	#if a true value is present then no dropping is performed
	#if a false or non existent value is present, session is closed
	$_dropper=sub {
		Log::OK::DEBUG and log_debug "Session: Dropper start";
		Log::OK::DEBUG and log_debug join ", " , caller;
		#Normal end of transaction operations
		$_rex=undef;


		$_fh or return;	#don't drop if already dropped
		return unless $_closeme or !@_;	#IF no error or closeme then return

		#End of session transactions
		#
		Log::OK::DEBUG and log_debug "Session: Dropper ".$_id;
		$_sr->pause;
		$_sw->pause;
		delete $_sessions->{$_id};
		close $_fh;
		$_fh=undef;
		$_id=undef;
		#$closeme=undef;

		#$self->[write_queue_]->@*=();
		#If the dropper was called with an argument that indicates no error
		if(@_ and @_zombies < 100){
			# NOTE: Complete reuses of a zombie may still be causing corruption
			# Suspect that the rex object is not being release intime 
			# when service static files.
			# Forced rex to be undef on IO error in static server.. Lets
			# see if that fixes the issue.
			# Otherwise comment out the line below
			unshift @_zombies, $self;
			Log::OK::DEBUG and log_debug "Pushed zombie";
		}
		else{
			#dropper was called without an argument. ERROR. Do not reuse 
			#
			#################################
			$_dropper=undef;      #
			undef $_sr->on_eof;            #
			undef $_sr->on_error;          #
			#                               #
			 undef $_sw->on_error; #
			# undef $self->[sw_];           #
			# undef $self->[sr_];           #
			 undef $self;                  #
			#################################
			Log::OK::DEBUG and log_debug "NO Pushed zombie";
		}

		Log::OK::DEBUG and log_debug "Session: zombies: ".@_zombies;
		
		Log::OK::DEBUG and log_debug "Session: Dropper: refcount:".SvREFCNT($self);	
		Log::OK::DEBUG and log_debug "Session: Dropper: refcount:".SvREFCNT($_dropper);	

		Log::OK::DEBUG and log_debug "Session: Dropper end";


	};

	$_sw->on_error=$_dropper;
	$_sw->timing(\$_time, \$Time);
	$_write=$_sw->writer;

	weaken $_write;
}

#take a zombie session and revive it
method revive {
	#say "revive  session";
	$_id=$_[0];	
	$_in_progress=undef;
	$_time=$Time;
	$_fh=$_[1];	
	$_scheme=$_[2];

	$_rex=undef;
	@_write_stack=();
	$_closeme=undef;
	$_sr->start($_fh);
	$_sw->set_write_handle($_fh);
	
	return $self;
}

#Accessors
method closeme :lvalue {
	$_closeme;
}

method dropper :lvalue {
	$_dropper;
}
method rex {
	$_rex;
}

method server {
	$_server;
}



#pluggable interface
#=====================
#

method push_reader {
	push @_read_stack, $_read=$_[1];
	$_sr->on_read=$_[1];
}

method push_writer {
	push @_write_stack, $_write;
	$_write=$_[1];
}

method pop_reader {
	pop @_read_stack;
	$_sr->on_read= $_read=$_read_stack[-1];
}

method pop_writer {
	pop @_write_stack;			#remove the previous
	my $name=$_write_stack[@_write_stack-1];
	#$self->[read_]=$self->[writer_cache_]{$name};
	#//=$make_reader_reg{$name}($self,@args));
	#$self->[read_]=$self->[read_stack_][@{$self->[read_stack_]}-1];
}

method set_writer {
	$_write=$_[1];
}

method pump_reader {
	$_sr->pump;
}

#timer for generating timestamps. 1 second resolution for HTTP date
my @months = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
my @days= qw(Sun Mon Tue Wed Thu Fri Sat);
our $timer=AE::timer 0,1, sub {
	my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = gmtime($Time=time);
	#export to globally available time?
	#
	#Format Tue, 15 Nov 1994 08:12:31 GMT
	#TODO: 0 padding of hour min sec
	$Date="$days[$wday], $mday $months[$mon] ".($year+1900).sprintf(" %02d:%02d:%02d",$hour, $min, $sec)." GMT";
	#say $Date;
	#say scalar $self->[zombies_]->@*;
	#say "Session count : ",scalar keys $self->[sessions_]->%*;
};


##################################################################################
# sub DESTROY {                                                                  #
#                                                                                #
#         Log::OK::DEBUG and log_debug "+++++++Session destroyed: $_[0]->[id_]"; #
# }                                                                              #
##################################################################################

1;
