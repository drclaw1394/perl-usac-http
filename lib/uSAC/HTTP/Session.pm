package uSAC::HTTP::Session;
use Object::Pad;
class uSAC::HTTP::Session;
use feature qw<say state refaliasing>;
no warnings "experimental";
use Log::ger;
use Log::OK;

use Scalar::Util 'openhandle','refaddr', 'weaken';
use Devel::Peek qw<SvREFCNT>;

use uSAC::IO::SReader;
use uSAC::IO::SWriter;
use IO::FD;
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
field $_time :mutator;
field $_closeme;
field $_rw;
field $_ww;
field $_wcb;
field $_left;
field $_read;
field $_write :mutator;
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
	($_id, $_fh, $_sessions, my $zombies, $_server, $_scheme)=@_;
	\my @zombies= $zombies;

	#make reader
        #######################################################
        # $_sr=uSAC::IO::SReader->create(fh=>$_fh);           #
        # $_sr->max_read_size=4096*16;                        #
        # ($_sr->on_eof = sub {$_closeme=1; $_dropper->(1)}); #
        # ($_sr->on_error=$_sr->on_eof);                      #
        # $_sr->timing(\$_time, \$Time);                      #
        #######################################################

        my $s=sub {$_closeme=1; $_dropper->(1)};
        $_sr=uSAC::IO::SReader->create(
                fh=>$_fh,
                max_read_size=>4096*16,
                on_eof =>$s,
                on_error=>$s,
                time=>\$_time,
                clock=>\$Time,
		on_read=>undef
        );
		


	$_sr->start;

	#make writer
	#$_sw=uSAC::IO::SWriter->create(fh=>$_fh);

	#Takes an a bool argument: keepalive
	#if a true value is present then no dropping is performed
	#if a false or non existent value is present, session is closed
	$_dropper=sub {
		Log::OK::DEBUG and log_debug "Session: Dropper start";
		Log::OK::DEBUG and log_debug "Session: args: @_";
		Log::OK::DEBUG and log_debug "Session: closeme: $_closeme";
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
		IO::FD::close $_fh;
		$_fh=undef;
		$_id=undef;
		#$closeme=undef;

		#$self->[write_queue_]->@*=();
		#If the dropper was called with an argument that indicates no error
		if(@_ and @zombies < 100){
			# NOTE: Complete reuses of a zombie may still be causing corruption
			# Suspect that the rex object is not being release intime 
			# when service static files.
			# Forced rex to be undef on IO error in static server.. Lets
			# see if that fixes the issue.
			# Otherwise comment out the line below
			unshift @zombies, $self;
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

		Log::OK::DEBUG and log_debug "Session: zombies: ".@zombies;
		
		Log::OK::DEBUG and log_debug "Session: Dropper: refcount:".SvREFCNT($self);	
		Log::OK::DEBUG and log_debug "Session: Dropper: refcount:".SvREFCNT($_dropper);	

		Log::OK::DEBUG and log_debug "Session: Dropper end";


	};

        $_sw=uSAC::IO::SWriter->create(
                fh=>$_fh,
                on_error=>$_dropper,
                time=>\$_time,
                clock=>\$Time,
        );
	
        ##############################################
        # $_sw=uSAC::IO::SWriter->create( fh=>$_fh); #
        # $_sw->on_error=$_dropper;                  #
        # $_sw->timing(\$_time, \$Time);             #
        ##############################################

	$_write=$_sw->writer;

	#weaken $_write;
}

#take a zombie session and revive it
method revive {
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
	
	#return $self;
}

method drop {
	$_dropper->(@_);
}

#Accessors
method closeme :lvalue {
	$_closeme;
}

method dropper :lvalue {
	$_dropper;
}
method rex :lvalue {
	$_rex;
}

method server {
	$_server;
}

method in_progress: lvalue{
	$_in_progress;
}

method fh :lvalue{
	$_fh;
}



#pluggable interface
#=====================
#

method push_reader {
	push @_read_stack, $_read=$_[0];
	$_sr->on_read=$_[0];
}

method push_writer {
	push @_write_stack, $_write;
	$_write=$_[0];
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
	$_write=$_[0];
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
};


#Return an array of references to variables which are publically editable
#Bypasses method calls for accessors
method exports {
	[\$_closeme,$_dropper, \$_server, \$_rex,\$_in_progress, $_write];

}
##################################################################################
# sub DESTROY {                                                                  #
#                                                                                #
#         Log::OK::DEBUG and log_debug "+++++++Session destroyed: $_[0]->[id_]"; #
# }                                                                              #
##################################################################################

1;
