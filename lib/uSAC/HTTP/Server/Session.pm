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
use enum ( "id_=0" ,qw<fh_ closeme_ rw_ rbuf_ ww_ wbuf_ wcb_ left_ read_ write_ request_count_ server_ read_stack_ write_stack_ current_reader_ reader_cache_ rex_ reader_cb_ on_body_>);

#Add a mechanism for sub classing
use constant KEY_OFFSET=>0;
use constant KEY_COUNT=>on_body_-id_+1;

use constant MAX_READ_SIZE => 128 * 1024;
#session represents the stack of protocols used by an application to ultimately write out
#to the filehandle
#

our %make_reader_reg;	#hash of sub references which will make a reader ref of a particular name

sub new {
	my $package=shift//__PACKAGE__;
	
	my $self=[];

	$self->[id_]=$_[0];	
	$self->[fh_]=$_[1];	
	$self->[server_]=$_[2];	

	$self->[wbuf_]="";
	$self->[rbuf_]="";
	$self->[read_stack_]=[];
	$self->[write_stack_]=[];

	$self->[on_body_]=undef;	#allocate all the storage now
	
	bless $self,$package;
	#make entry on the write stack
	$self->[write_]=$self->_make_writer($self,0);
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

	
	$self->[write_]=$self->_make_writer($self, 0);
        $self->_make_reader;

	return $self;
}

sub _make_reader {
	my $self=shift;
	weaken $self;
	my $fh=$self->[fh_];
	\my $buf=\$self->[rbuf_];
	my $ref=\$self->[rbuf_];	
	my $len;
	#say "Make reader";
	#create first entry into the read stack
	$self->[rw_] = AE::io $fh, 0, sub {
		$len = sysread( $fh, $buf, MAX_READ_SIZE, length $buf );
		given($len){
			when($_>0){
				$self->[read_]($ref,$self->[rex_],$self->[reader_cb_]);
			}
			when(0){
				#End of file
				$self->[closeme_]=1;
				drop $self;
			}
			when(undef){
				#potential error
				#say "Error maybe?";
				return if $! == EAGAIN or $! == EINTR; #or $! == WSAEWOULDBLOCK;
				$self->[closeme_]=1;
				drop $self;
			}
			default {
			}
		}
	};
}

sub _make_writer{
	#take a session and alias the variables to lexicals
	my $ido=shift;
	weaken $ido;
	#my $stackPos=shift;
	#my $server=$ido->[uSAC::HTTP::Server::Session::server_];
	\my $wbuf=\$ido->[uSAC::HTTP::Server::Session::wbuf_];
	\my $ww=\$ido->[uSAC::HTTP::Server::Session::ww_];
	\my $fh=\$ido->[uSAC::HTTP::Server::Session::fh_];
	
	my $w;
	sub {
		\my $buf=\$_[0];	#give the input a name
		$ido->[wcb_]=$_[1] if defined $_[1];
		my $cb=$ido->[wcb_];
		#say "WRITE DATA: $buf";
		if(length($wbuf) == 0 ){
			$w = syswrite( $fh, $buf );
			given ($w){
				when(length $buf){
					#say "FULL WRITE NO APPEND";
					$wbuf="";
					#$ww=undef;
					$cb->() if defined $cb;
					return;

				}
				when(length($buf)> $w){
					say "PARITAL WRITE NO APPEND";
					$wbuf.=substr($buf,$w);
					return if defined $ww;

				}
				default {
					unless( $! == EAGAIN or $! == EINTR){
						say "ERROR IN WRITE NO APPEND";
						#actual error		
						$ww=undef;
						#$wbuf="";
						$ido->drop( "$!");
						return;
					}
				}
			}

		}
		else {
			$wbuf.= $buf;
			$w = syswrite( $fh, $wbuf );
			given($w){
				when(length $wbuf){
					$ww=undef;
					$wbuf="";
					$cb->() if defined $cb;
					return;
				}
				when (length($wbuf)> $w){
					$wbuf.=substr($wbuf,$w);
					#need to create watcher if it does
					return if defined $ww;

				}
				default{
					#error
					unless( $! == EAGAIN or $! == EINTR){
						#actual error		
						$ww=undef;
						#$wbuf="";
						$ido->drop( "$!");
						return;
					}
					return if defined $ww;
				}
			}
		}

		say "making watcher";
		$ww = AE::io $fh, 1, sub {
			#say "IN WRITE WATCHER CB";
			$ido or return;
			$w = syswrite( $fh, $wbuf );
			given($w){
				when(length $wbuf) {
					$wbuf="";
					undef $ww;
					$ido->[wcb_]->() if defined $ido->[wcb_];
					#if( $ido->[closeme_] ) { $ido->drop(); }
				}
				when(defined $w){
					$wbuf= substr( $wbuf, $w );
				}
				default {
					#error
					return if $! == EAGAIN or $! == EINTR;#or $! == WSAEWOULDBLOCK){
					#actual error		
					$ww=undef;
					$wbuf="";
					$ido->drop( "$!");
					return;
				}
			}
		};
		#else { return $ido->drop("$!"); }
	};
}


sub drop {
        my ($self,$err) = @_;
	return unless $self->[closeme_];
        my $r = delete $self->[server_][uSAC::HTTP::Server::sessions_]{$self->[id_]}; #remove from server
        $self->[server_][uSAC::HTTP::Server::active_connections_]--;

	close $self->[fh_];
	
	$self->@[(rw_,ww_,,fh_,id_,closeme_)]=(undef) x 7;

	$self->[write_stack_][0]=undef;
	$self->[read_stack_]=[];
	$self->[wbuf_]=undef;
	$self->[rbuf_]=undef;

	unshift @{$self->[server_][uSAC::HTTP::Server::zombies_]}, $self;

        ###############################################################################################################################
        # ( delete $self->[server_][uSAC::HTTP::Server::graceful_] )->()                                                              #
        #         if $self->[server_][uSAC::HTTP::Server::graceful_] and $self->[server_][uSAC::HTTP::Server::active_requests_] == 0; #
        ###############################################################################################################################
}

#pluggable interface
#=====================
#

sub push_reader {
	my ($self,$name,$cb)=@_;
	$self->[read_]=($self->[reader_cache_]{$name}//=$make_reader_reg{$name}($self));#,@args));
	push $self->[read_stack_]->@*, $name;
	$self->[reader_cb_]=$cb;
}

#Reuse the previous reader in the stack
#Does not attempt to remake it...
sub pop_reader {
	my ($self)=@_;
	pop @{$self->[read_stack_]};			#remove the previous
	my $name=$self->[read_stack_]->@[$self->[read_stack_]->@*-1];;		#
	$self->[read_]=$self->[reader_cache_]{$name};
	say "Read stack after pop: ",$self->[read_stack_]->@*;
	#//=$make_reader_reg{$name}($self,@args));
	#$self->[read_]=$self->[read_stack_][@{$self->[read_stack_]}-1];
}



1;
