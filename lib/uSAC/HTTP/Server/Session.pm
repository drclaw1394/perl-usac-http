package uSAC::HTTP::Server::Session;
use common::sense;
use Data::Dumper;
use feature "refaliasing";
no warnings "experimental";
use Scalar::Util 'refaddr', 'weaken';

#require uSAC::HTTP::Server;
use EV;
use AnyEvent;
use Data::Dumper;
use uSAC::HTTP::Server;

use Errno qw(EAGAIN EINTR);
use AnyEvent::Util qw(WSAEWOULDBLOCK guard AF_INET6 fh_nonblocking);
#Session represents a logical connection. could be tcp or application defined UDP
#
#
#Class attribute keys
use enum ( "id_=0" ,qw<fh_ closeme_ rw_ rbuf_ ww_ wbuf_ wcb_ left_ read_ write_ request_count_ server_ read_stack_ write_stack_ current_reader_ reader_cache_ writer_cache_ rex_ reader_cb_ writer_cb_ on_body_>);

#Add a mechanism for sub classing
use constant KEY_OFFSET=>0;
use constant KEY_COUNT=>on_body_-id_+1;

use constant MAX_READ_SIZE => 128 * 1024;
#session represents the stack of protocols used by an application to ultimately write out
#to the filehandle
#

our %make_reader_reg;	#hash of sub references which will make a reader ref of a particular name
our %make_writer_reg;	#hash of sub references which will make a writer ref of a particular name

sub new {
	my $package=shift//__PACKAGE__;
	
	my $self=[];

	$self->[id_]=$_[0];	
	$self->[fh_]=$_[1];	
	$self->[server_]=$_[2];	

	$self->[wbuf_]="";
	$self->[rbuf_]="";
	#$self->[read_stack_]=[];
	#$self->[reader_cache_]={};

	#$self->[write_stack_]=[];
	#$self->[writer_cache_]={};

	$self->[on_body_]=undef;	#allocate all the storage now
	
	bless $self,$package;
	#make entry on the write stack
	$self->_make_reader;
	
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
	#$self->[server_]=$_[2];	

	
        $self->_make_reader;

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

	#say "Make reader";
	#create first entry into the read stack
	$self->[rw_] = AE::io $fh, 0, sub {
		$len = sysread( $fh, $buf, MAX_READ_SIZE, length $buf );
		#say "READ BUFFER: ",$buf;
		given($len){
			when($_>0){
				$reader->();
			}
			when(0){
				#End of file
				#say "END OF  READER";
				$self->[closeme_]=1;
				drop $self;
				$self->[rw_]=undef;
			}
			when(undef){
				#potential error

				return if $! == EAGAIN or $! == EINTR; #or $! == WSAEWOULDBLOCK;
				#say "ERROR IN READER";
				$self->[closeme_]=1;
				drop $self;
				$self->[rw_]=undef;
			}
			default {
			}
		}
	};
}


sub drop {
        my ($self,$err) = @_;
	return unless $self->[closeme_];
        my $r = delete $self->[server_][uSAC::HTTP::Server::sessions_]{$self->[id_]}; #remove from server
        $self->[server_][uSAC::HTTP::Server::active_connections_]--;

	close $self->[fh_];
	$self->[fh_]=undef;
	$self->@[(rw_,ww_,fh_,id_,closeme_)]=(undef) x 5;

	$self->[write_stack_]=[];#[0]=undef;
	$self->[read_stack_]=[];
	$self->[wbuf_]=undef;
	$self->[rbuf_]=undef;

	unshift @{$self->[server_][uSAC::HTTP::Server::zombies_]}, $self;
}

#pluggable interface
#=====================
#

sub push_reader {
	my ($self,$name,$cb)=@_;

	$self->[reader_cb_]=$cb;	#set the reader callback
	$self->[read_]=($self->[reader_cache_]{$name}//=$make_reader_reg{$name}($self));#,@args));
	push $self->[read_stack_]->@*, $name;
	#say "reader cb: ", $cb;
}

sub push_writer {
	my ($self,$name,$cb)=@_;
	$self->[writer_cb_]=$cb;	#cb to call when write needs more data/is complete
	$self->[write_]=($self->[writer_cache_]{$name}//=$make_writer_reg{$name}($self));#,@args));
	push $self->[write_stack_]->@*, $name;
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



1;
