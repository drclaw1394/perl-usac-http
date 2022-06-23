package uSAC::HTTP::Session;
use feature qw<say state refaliasing>;
no warnings "experimental";
use Log::ger;
use Log::OK;

use Scalar::Util 'openhandle','refaddr', 'weaken';
use Devel::Peek qw<SvREFCNT>;
use uSAC::SIO::AE::SReader;
use uSAC::SIO::AE::SWriter;
use Data::Dumper;


#require uSAC::HTTP::Server;
use EV;
use AnyEvent;
#use uSAC::HTTP::Server;

use Errno qw(EAGAIN EINTR);
#Session represents a logical connection. could be tcp or application defined UDP
#
#
#Class attribute keys
use enum ( "id_=0" ,qw<fh_ sessions_ zombies_ server_ scheme_ time_ closeme_ rw_ ww_ wcb_ left_ read_ write_ request_count_ read_stack_ write_stack_ current_reader_ reader_cache_ writer_cache_ rex_ dropper_ write_queue_ sr_ sw_ in_progress_ on_body_>);

#Add a mechanism for sub classing
use constant KEY_OFFSET=>0;
use constant KEY_COUNT=>on_body_-id_+1;

use constant MAX_READ_SIZE => 128 * 1024;
#session represents the stack of protocols used by an application to ultimately write out
#to the filehandle
#

#our %make_reader_reg;	#hash of sub references which will make a reader ref of a particular name
#our %make_writer_reg;	#hash of sub references which will make a writer ref of a particular name


our $Date;		#Date string for http
our $Time;		#seconds from epoch

sub _make_reader;
sub drop;

sub new {
	my $package=shift//__PACKAGE__;
	
	#my $self=[];
	my $self=\@_;
        $self->[time_]=$Time; 

	#$self->[read_stack_]=[];
	$self->[reader_cache_]={};

	$self->[write_stack_]=[];
	#
	my $server=$self->[server_];
	my $sessions=$self->[sessions_];
	#my $zombies=$self->[zombies_];
	\my $fh=\$self->[fh_];
	\my $id=\$self->[id_];
	\my $closeme=\$self->[closeme_];

	#make reader
	my $sr=uSAC::SIO::AE::SReader->new($self->[fh_]);
	$sr->max_read_size=4096*16;
	#$sr->on_read=\$self->[read_];
	($sr->on_eof = sub {$self->[closeme_]=1; $self->[dropper_]->()});
	($sr->on_error=$sr->on_eof);
	$sr->timing(\$self->[time_], \$Time);
	$self->[sr_]=$sr;


	uSAC::SIO::AE::SReader::start $sr;
	#$sr->start;

	#make writer
	$self->[sw_]=uSAC::SIO::AE::SWriter->new($self->[fh_]);

	#Takes an a bool argument: keepalive
	#if a true value is present then no dropping is performed
	#if a false or non existent value is present, session is closed
	$self->[dropper_]=sub {
		Log::OK::DEBUG and log_debug "Session: Dropper start";
		Log::OK::DEBUG and log_debug join ", " , caller;
		#Normal end of transaction operations
		$self->[rex_]=undef;


		$fh or return;	#don't drop if already dropped
		return unless $closeme or !@_;

		#End of session transactions
		#
		Log::OK::DEBUG and log_debug "Session: Dropper ".$self->[id_];
		$self->[sr_]->pause;
		$self->[sw_]->pause;
		delete $sessions->{$self->[id_]};
		close $fh;
		$fh=undef;
		$id=undef;
		#$closeme=undef;

		#$self->[write_queue_]->@*=();
		
		#If the dropper was called with an argument that indicates no error
		if(@_ and $self->[zombies_]->@* < 100){
			# NOTE: Complete reuses of a zombie may still be causing corruption
			# Suspect that the rex object is not being release intime 
			# when service static files.
			# Forced rex to be undef on IO error in static server.. Lets
			# see if that fixes the issue.
			# Otherwise comment out the line below
			unshift @{$self->[zombies_]}, $self;
		}
		else{
			#dropper was called without an argument. ERROR. Do not reuse 
			#
			#################################
			$self->[dropper_]=undef;      #
			undef $sr->on_eof;            #
			undef $sr->on_error;          #
			#                               #
			 undef $self->[sw_]->on_error; #
			# undef $self->[sw_];           #
			# undef $self->[sr_];           #
			 undef $self;                  #
			#################################
		}

		Log::OK::DEBUG and log_debug "Session: zombies: ".$self->[zombies_]->@*;
		
		Log::OK::DEBUG and log_debug "Session: Dropper: refcount:".SvREFCNT($self);	
		Log::OK::DEBUG and log_debug "Session: Dropper: refcount:".SvREFCNT($self->[dropper_]);	

		Log::OK::DEBUG and log_debug "Session: Dropper end";


	};

	($self->[sw_]->on_error=$self->[dropper_]);
	$self->[sw_]->timing(\$self->[time_], \$Time);
	$self->[write_]=$self->[sw_]->writer;

	weaken $self->[write_];

	bless $self,$package;
	#make entry on the write stack
	#$self;
}

#take a zombie session and revive it
sub revive {
	#say "revive  session";
	my $self=shift;
	$self->[id_]=$_[0];	
	$self->[in_progress_]=undef;
	$self->[time_]=$Time;
	$self->[fh_]=$_[1];	
	$self->[scheme_]=$_[2];
	$self->[rex_]=undef;
	#$self->[write_queue_]->@*=();
	$self->[write_stack_]=[];
	$self->[closeme_]=undef;
	uSAC::SIO::AE::SReader::start $self->[sr_], $self->[fh_];
	$self->[sw_]->set_write_handle($self->[fh_]);

	
	return $self;
}

#Accessors
sub server {
	$_[0][server_];
}



#pluggable interface
#=====================
#

sub push_reader {
	push $_[0][read_stack_]->@*, $_[0][read_]=$_[1];
	$_[0][sr_]->on_read=$_[1];
}

sub push_writer {
	push $_[0][write_stack_]->@*, $_[0][write_];
	$_[0][write_]=$_[1];
}

sub pop_reader {
	pop $_[0][read_stack_]->@*;
	$_[0][sr_]->on_read= $_[0][read_]=$_[0][read_stack_][-1];
}

sub pop_writer {
	my ($self)=@_;
	pop @{$self->[write_stack_]};			#remove the previous
	my $name=$self->[write_stack_]->@[$self->[write_stack_]->@*-1];
	#$self->[read_]=$self->[writer_cache_]{$name};
	#//=$make_reader_reg{$name}($self,@args));
	#$self->[read_]=$self->[read_stack_][@{$self->[read_stack_]}-1];
}

sub set_writer {
	$_[0]->[write_]=$_[1];
}

sub pump_reader {
	$_[0][sr_]->pump;
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
