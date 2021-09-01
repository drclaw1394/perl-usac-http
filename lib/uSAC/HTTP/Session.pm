package uSAC::HTTP::Session;
use common::sense;
use Data::Dumper;
use feature "refaliasing";
no warnings "experimental";
use Scalar::Util 'refaddr', 'weaken';

#require uSAC::HTTP::Server;
use EV;
use AnyEvent;
use Data::Dumper;
#use uSAC::HTTP::Server;

use Errno qw(EAGAIN EINTR);
use AnyEvent::Util qw(WSAEWOULDBLOCK guard AF_INET6 fh_nonblocking);
#Session represents a logical connection. could be tcp or application defined UDP
#
#
#Class attribute keys
use enum ( "id_=0" ,qw<fh_ closeme_ rw_ rbuf_ ww_ wbuf_ wcb_ left_ read_ write_ request_count_ server_ sessions_ zombies_ read_stack_ write_stack_ current_reader_ reader_cache_ writer_cache_ rex_ reader_cb_ writer_cb_ dropper_ on_body_>);

#Add a mechanism for sub classing
use constant KEY_OFFSET=>0;
use constant KEY_COUNT=>on_body_-id_+1;

use constant MAX_READ_SIZE => 128 * 1024;
#session represents the stack of protocols used by an application to ultimately write out
#to the filehandle
#

our %make_reader_reg;	#hash of sub references which will make a reader ref of a particular name
our %make_writer_reg;	#hash of sub references which will make a writer ref of a particular name


our $Date;

sub _make_reader;
sub drop;

sub new {
	my $package=shift//__PACKAGE__;
	
	my $self=[];

	$self->[id_]=$_[0];	
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

	$self->[on_body_]=undef;	#allocate all the storage now
	#$self->[dropper_]=make_dropper($self);
	#
	my $server=$self->[server_];
	my $sessions=$self->[sessions_];
	my $zombies=$self->[zombies_];
	\my $fh=\$self->[fh_];
	\my $rw=\$self->[rw_];
	\my $ww=\$self->[ww_];
	\my $id=\$self->[id_];
	\my $closeme=\$self->[closeme_];
	$self->[dropper_]=sub {
		return unless $closeme;
		delete $sessions->{$id};
		close $fh;
		$rw=undef;
		$ww=undef;
		$fh=undef;
		$id=undef;
		$closeme=undef;
		#say "DROP COMPLETE...";

	unshift @$zombies, $self;

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
	$self->[fh_]=$_[1];	
	$self->[wbuf_]="";
	$self->[rbuf_]="";
	$self->[rex_]=undef;

	
	#$self->_make_reader;
	#_make_reader $self;

	return $self;
}

sub _make_reader {
	my $self=shift;
	weaken $self;
	\my $fh=\$self->[fh_];
	\my $buf=\$self->[rbuf_];
	#my $ref=\$self->[rbuf_];	
	my $len;
	\my $reader=\$self->[read_];

	$self->[rw_] = AE::io $fh, 0, sub {
		$len = sysread( $fh, $buf, MAX_READ_SIZE, length $buf );
		if($len>0){
			$reader->();
		}
		#when(0){
		elsif($len==0){

			#End of file
			#say "END OF  READER";
			$self->[closeme_]=1;
			drop $self;
			$self->[rw_]=undef;
		}
		#when(undef){
		else {
			#potential error
			#say "ERROR";
			return if $! == EAGAIN or $! == EINTR;
			#say "ERROR IN READER";
			$self->[closeme_]=1;
			drop $self;
			$self->[rw_]=undef;
		}
	};
}
#############################################
# sub make_dropper {                        #
#         my $self=shift;                   #
#         my $server=$self->[server_];      #
#         my $sessions=$self->[sessions_];  #
#         my $zombies=$self->[zombies_];    #
#         \my $fh=\$self->[fh_];            #
#         \my $rw=\$self->[rw_];            #
#         \my $ww=\$self->[ww_];            #
#         \my $id=\$self->[id_];            #
#         \my $closeme=\$self->[closeme_];  #
#         sub {                             #
#                 say "IN DROPPER";         #
#                 return unless $closeme;   #
#                 delete $sessions->{$id};  #
#                 close $fh;                #
#                 $rw=undef;                #
#                 $ww=undef;                #
#                 $fh=undef;                #
#                 $id=undef;                #
#                 $closeme=undef;           #
#                                           #
#                 unshift @$zombies, $self; #
#         }                                 #
# }                                         #
#                                           #
#############################################
sub drop {
	#my ($self,$err) = @_;
	return unless $_[0]->[closeme_];
	my $r = delete $_[0]->[server_][sessions_]{$_[0]->[id_]}; #remove from server
	#$_[0]->[server_][uSAC::HTTP::Server::active_connections_]--;

	close $_[0]->[fh_];

	$_[0]->[fh_]=undef;
	$_[0]->@[(rw_,ww_,fh_,id_,closeme_)]=(undef,undef,undef,undef,undef);#(undef) x 5;

	#$_[0]->[write_stack_]=undef;	#[];#[0]=undef;
	#$_[0]->[read_stack_]=undef;	#[];

	unshift @{$_[0]->[zombies_]}, $_[0];
	say "DROP COMPLETE...";
}

#pluggable interface
#=====================
#

sub push_reader {
	my ($self,$name,$cb)=@_;

	$self->[reader_cb_]=$cb;	#set the reader callback
	$self->[read_]=($self->[reader_cache_]{$name}//=$make_reader_reg{$name}($self));#,@args));
	#push $self->[read_stack_]->@*, $name;
	#say "reader cb: ", $cb;
}

sub push_writer {
	my ($self,$name,$cb)=@_;
	#$self->[writer_cb_]=$cb;	#cb to call when write needs more data/is complete
	$self->[write_]=($self->[writer_cache_]{$name}//=$make_writer_reg{$name}($self));#,@args));
	#push $self->[write_stack_]->@*, $name;
	#$self->[reader_cb_]=$cb;
}

#Reuse the previous reader in the stack
#Does not attempt to remake it...
sub pop_reader {
	my ($self)=@_;
	pop @{$self->[read_stack_]};			#remove the previous
	my $name=$self->[read_stack_]->@[$self->[read_stack_]->@*-1];;		#
	$self->[read_]=$self->[reader_cache_]{$name};
	#//=$make_reader_reg{$name}($self,@args));
	#$self->[read_]=$self->[read_stack_][@{$self->[read_stack_]}-1];
}
sub pop_writer {
	my ($self)=@_;
	pop @{$self->[write_stack_]};			#remove the previous
	my $name=$self->[write_stack_]->@[$self->[write_stack_]->@*-1];
	$self->[read_]=$self->[writer_cache_]{$name};
	#//=$make_reader_reg{$name}($self,@args));
	#$self->[read_]=$self->[read_stack_][@{$self->[read_stack_]}-1];
}

sub select_writer{
	my ($self,$name)=@_;
	#	say "In select writer";
	#say %make_writer_reg;
	$self->[writer_cache_]{$name}//=$make_writer_reg{$name}($self);
}

#timer for generating timestamps. 1 second resolution for HTTP date
our $timer=AE::timer 0,1, sub {
	state @months = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
	state @days= qw(Sun Mon Tue Wed Thu Fri Sat);
	my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) =gmtime;
	#export to globally available time?
	#
	#Format Tue, 15 Nov 1994 08:12:31 GMT
	#TODO: 0 padding of hour min sec
	$Date="$days[$wday], $mday $months[$mon] ".($year+1900)." $hour:$min:$sec GMT";
	#say scalar $self->[zombies_]->@*;
	#say "Session count : ",scalar keys $self->[sessions_]->%*;
};

1;
