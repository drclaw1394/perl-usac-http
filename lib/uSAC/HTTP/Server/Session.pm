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
use enum ( "id_=0" ,qw<fh_ closeme_ rw_ rbuf_ ww_ wbuf_ left_ read_ write_ request_count_ server_ read_stack_ write_stack_ on_body_>);

#Add a mechanism for sub classing
use constant KEY_OFFSET=>0;
use constant KEY_COUNT=>on_body_-id_+1;

use constant MAX_READ_SIZE => 128 * 1024;
#session represents the stack of protocols used by an application to ultimately write out
#to the filehandle
#
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

	$$self[on_body_]=undef;	#allocate all the storage now
	
	bless $self,$package;
	#make entry on the write stack
	$self->_make_reader;
	$self->push_writer(\&make_writer);	
	$self;
}

#take a zombie session and revive it
sub revive {
	my $self=shift;
	$self->[id_]=$_[0];	
	$self->[fh_]=$_[1];	
	#$self->[server_]=$_[2];	

        ######################################
        # #$self->[wbuf_]="";                #
        # #$self->[rbuf_]="";                #
        # $self->[read_stack_]=[];           #
        # $self->[write_stack_]=[];          #
        #                                    #
        # $self->_make_reader;               #
        # $self->push_writer(\&make_writer); #
        # $self;                             #
        #                                    #
        # return $self;                      #
        # $self->[id_]=$_[0];                #
        # $self->[fh_]=$_[1];                #
        # #$self->[server_]=$_[2];           #
        ######################################
	
        $self->_make_reader;

	my $wr=make_writer($self, 0);
	$self->[write_stack_][0]=$wr;
	$self->[write_]=$wr;

	
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
		#$self and $r or return;
		#$self and exists $self->[sessions_]{$id} or return;
		$len = sysread( $fh, $buf, MAX_READ_SIZE, length $buf );
		#say "buffer length : ", length $buf, "last read len: $len";
		#sleep 1;
		given($len){
			when($_>0){
				#run through protostack
				#say "read $buf and calling stack";
				$self->[read_stack_][0]->($ref);#\$buf);
			}
			when(0){
				#End of file
				$self->[closeme_]=1;
				drop $self;
			}
			when(undef){
				#potential error
				#say "Error maybe?";
				return if $! == EAGAIN or $! == EINTR or $! == WSAEWOULDBLOCK;
				#say "Yep error";
				$self->[closeme_]=1;
				drop $self;
			}
			default {
			}
		}
	};
}

sub make_writer{
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
		#		my $cb=$_[1];
		#say "WRITE DATA: $buf";
		if(length($wbuf)== 0 ){
			$w = syswrite( $fh, $buf );
			given ($w){
				when(length $buf){
					#say "FULL WRITE NO APPEND";
					#$wbuf="";
					#$ww=undef;
					$_[1]->() if defined $_[1];
					return;

				}
				when(length($buf)> $w){
					say "PARITAL WRITE NO APPEND";
					$wbuf.=substr($buf,$w);
					return if defined $ww;

				}
				default {
					if($! == EAGAIN or $! == EINTR or $! == WSAEWOULDBLOCK){
						say "ERROR IN WRITE NO APPEND";
						#actual error		
						$ww=undef;
						$wbuf="";
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
					$_[1]->() if defined $_[1];
					return;
				}
				when (length($wbuf)> $w){
					$wbuf.=substr($wbuf,$w);
					#need to create watcher if it does
					return if defined $ww;

				}
				default{
					#error
					if($! == EAGAIN or $! == EINTR or $! == WSAEWOULDBLOCK){
						#actual error		
						$ww=undef;
						$wbuf="";
						$ido->drop( "$!");
						return;
					}
				}
			}
		}

		$ido->[uSAC::HTTP::Server::Session::ww_] = AE::io $fh, 1, sub {
			#say "IN WRITE WATCHER CB";
			$ido or return;
			$w = syswrite( $fh, $wbuf );
			given($w){
				when(length $wbuf) {
					$wbuf="";
					undef $ww;
					if(defined $_[1]){
						$_[1]->();
					}
					if( $ido->[uSAC::HTTP::Server::Session::closeme_] ) { $ido->drop(); }
				}
				when(defined $w){
					$wbuf= substr( $wbuf, $w );
				}
				default {
					#error
					if($! == EAGAIN or $! == EINTR or $! == WSAEWOULDBLOCK){
						#actual error		
						$ww=undef;
						$wbuf="";
						$ido->drop( "$!");
						return;
					}
				}
			}
		};
		#else { return $ido->drop("$!"); }
	};
}


sub drop {
        my ($self,$err) = @_;
	return unless $self->[closeme_];
	#say "DROPPING";
        my $r = delete $self->[server_][uSAC::HTTP::Server::sessions_]{$self->[id_]}; #remove from server
        $self->[server_][uSAC::HTTP::Server::active_connections_]--;
	#@{ $r } = () if $r;
	#@{$self}=();
	$self->@[(rw_,ww_,write_,read_,fh_,id_,closeme_)]=(undef) x 7;
        ############################
        # $self->[rw_]=undef;      #
        # $self->[ww_]=undef;      #
        # $self->[write_]=undef;   #
        # $self->[read_]=undef;    #
        # $self->[fh_]=undef;      #
        # $self->[id_]=undef;      #
        # $self->[closeme_]=undef; #
        ############################
	unshift @{$self->[server_][uSAC::HTTP::Server::zombies_]}, $self;

        ###############################################################################################################################
        # ( delete $self->[server_][uSAC::HTTP::Server::graceful_] )->()                                                              #
        #         if $self->[server_][uSAC::HTTP::Server::graceful_] and $self->[server_][uSAC::HTTP::Server::active_requests_] == 0; #
        ###############################################################################################################################
}

sub push_writer {
	my ($self,$maker_sub,@args)=@_;	#pass the sub which will make the writer sub,
	given($self->[write_stack_]){
                ######################################
                # say  "Self: ",Dumper $self;        #
                # say  "Write stack: ",Dumper $_;    #
                # say  "maker: ", Dumper $maker_sub; #
                ######################################
		push @{$_},$maker_sub->($self,@{$_},@args); #session, index of new writer, args to maker
	}

	$self->[write_]=$self->[write_stack_][@{$self->[write_stack_]}-1];
	#retusn the writer created
}

sub pop_writer {
	my ($self)=@_;
	pop @{$self->[write_stack_]};

	$self->[write_]=$self->[write_stack_][@{$self->[write_stack_]}-1];
}

sub push_reader {
	my ($self,$maker_sub, @args)=@_;
	given($self->[read_stack_]){
                ##################################
                # say  "Self: ",Dumper $self;    #
                # say  "Read stack: ",Dumper $_; #
                ##################################
		push @{$_},$maker_sub->($self,@{$_},@args); #session, index of new reader, args to maker
	}
	$self->[read_]=$self->[read_stack_][@{$self->[read_stack_]}-1];
	#now force execution of reader 
	#$self->[read_]->(\$self->[rbuf_]);
}
# cancel existing read watcher
# create new watcher from top of stack
# pop the stack
sub pop_reader {
	my ($self)=@_;
	pop @{$self->[read_stack_]};

	$self->[read_]=$self->[read_stack_][@{$self->[read_stack_]}-1];
}



1;
