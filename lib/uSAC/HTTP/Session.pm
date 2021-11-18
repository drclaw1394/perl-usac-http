package uSAC::HTTP::Session;
use common::sense;
use feature "refaliasing";
no warnings "experimental";
use Scalar::Util 'openhandle','refaddr', 'weaken';

#require uSAC::HTTP::Server;
use EV;
use AnyEvent;
#use uSAC::HTTP::Server;

use Errno qw(EAGAIN EINTR);
use AnyEvent::Util qw(WSAEWOULDBLOCK guard AF_INET6 fh_nonblocking);
#Session represents a logical connection. could be tcp or application defined UDP
#
#
#Class attribute keys
use enum ( "id_=0" ,qw<time_ fh_ closeme_ rw_ rbuf_ ww_ wbuf_ wcb_ left_ read_ write_ request_count_ server_ sessions_ zombies_ read_stack_ write_stack_ current_reader_ reader_cache_ writer_cache_ rex_ reader_cb_ writer_cb_ dropper_ write_queue_ on_body_>);

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
	
	my $self=[];

	$self->[id_]=$_[0];	
	$self->[time_]=$Time;
	$self->[fh_]=$_[1];	
	$self->[sessions_]=$_[2];	
	$self->[zombies_]=$_[3];	
	$self->[server_]=$_[4];

	$self->[wbuf_]="x"x(4096*16);
	$self->[wbuf_]="";
	$self->[rbuf_]="";
	#$self->[read_stack_]=[];
	#$self->[reader_cache_]={};

	#$self->[write_stack_]=[];
	#$self->[writer_cache_]={};

	$self->[write_queue_]=[];
	$self->[on_body_]=undef;	#allocate all the storage now
	#$self->[dropper_]=make_dropper($self);
	#
	my $server=$self->[server_];
	my $sessions=$self->[sessions_];
	#my $zombies=$self->[zombies_];
	\my $fh=\$self->[fh_];
	\my $rw=\$self->[rw_];
	\my $ww=\$self->[ww_];
	\my $id=\$self->[id_];
	\my $closeme=\$self->[closeme_];
	$self->[dropper_]=sub {
		#say "Close me: $closeme";

		return unless $closeme||$_[0];
		delete $sessions->{$id};
		close $fh;
		$rw=undef;
		$ww=undef;
		$fh=undef;
		$id=undef;
		$closeme=undef;
		$self->[write_queue_]->@*=();
		unshift @{$self->[zombies_]}, $self;
		#say caller;
		#say "DROP COMPLETE...";


	};

	
	bless $self,$package;
	#make entry on the write stack
	#$self->_make_reader;
	#_make_reader $self;	
	$self;
}

#take a zombie session and revive it
sub revive {
	my $self=shift;
	$self->[id_]=$_[0];	
	$self->[time_]=$Time;
	$self->[fh_]=$_[1];	
	$self->[wbuf_]="";
	$self->[rbuf_]="";
	$self->[rex_]=undef;
	$self->[write_queue_]->@*=();

	
	#$self->_make_reader;
	#_make_reader $self;

	return $self;
}

sub _make_reader {
	my $self=shift;
	weaken $self;
	my $fh=$self->[fh_];
	\my $buf=\$self->[rbuf_];
	my $len;
	\my $reader=\$self->[read_];

	$self->[rw_] = AE::io $fh, 0, sub {
		$self->[time_]=$Time;	#Update the last access time
		$len = sysread( $fh, $buf, MAX_READ_SIZE, length $buf );
		#say $buf;
		if($len>0){
			#say "Calling reader: ", $reader;
			$reader->();
		}
		#when(0){
		elsif($len==0){
			#say "read len is zero";
                        #End of file
			#say "END OF  READER";
			$self->[closeme_]=1;
			$self->[rw_]=undef;
			$self->[dropper_]->();
		}
		#when(undef){
		else {
			#potential error
			#say "ERROR";
			return if $! == EAGAIN or $! == EINTR;
			say "ERROR IN READER";
			$self->[closeme_]=1;
			$self->[dropper_]->();
			$self->[rw_]=undef;
		}
	};
}

#pluggable interface
#=====================
#

sub push_reader {
	push $_[0][read_stack_]->@*, $_[0][read_]=$_[1];
	#$_[0][reader_cb_]=$_[2];
}

sub push_writer {
	$_[0][write_]=$_[1];
}

sub pop_reader {
	pop $_[0][read_stack_]->@*;
	$_[0][read_]=$_[0][read_stack_][-1];
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

#timer for generating timestamps. 1 second resolution for HTTP date
our $timer=AE::timer 0,1, sub {
	state @months = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
	state @days= qw(Sun Mon Tue Wed Thu Fri Sat);
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


1;
