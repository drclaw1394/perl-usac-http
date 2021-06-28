package uSAC::HTTP::Server::Session;
use common::sense;
use feature "refaliasing";
no warnings "experimental";

#require uSAC::HTTP::Server;
use Data::Dumper;
use uSAC::HTTP::Server;
#Session represents a logical connection. could be tcp or application defined UDP
#
#
#Class attribute keys
use enum ( "id_=0" ,qw<fh_ closeme_ rw_ rbuf_ ww_ wbuf_ left_ read_ write_ request_count_ server_ read_stack_ write_stack_ on_body_>);

#Add a mechanism for sub classing
use constant KEY_OFFSET=>0;
use constant KEY_COUNT=>on_body_-id_+1;

#session represents the stack of protocols used by an application to ultimately write out
#to the filehandle
#
sub new {
	my $self=[];
	$$self[on_body_]=undef;	#allocate all the storage now
	bless $self,__PACKAGE__;
}

sub drop {
        my ($self,$err) = @_;
        $err =~ s/\015//sg if defined $err;
        my $r = delete $self->[server_][uSAC::HTTP::Server::sessions_]{$self->[id_]}; #remove from server
        $self->[server_][uSAC::HTTP::Server::active_connections_]--;
        @{ $r } = () if $r;

        ( delete $self->[server_][uSAC::HTTP::Server::graceful_] )->()
                if $self->[server_][uSAC::HTTP::Server::graceful_] and $self->[server_][uSAC::HTTP::Server::active_requests_] == 0;
}

sub push_writer {
	my ($self,$maker_sub,@args)=@_;	#pass the sub which will make the writer sub,
	given($self->[write_stack_]){
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

#raw writer. 

#http1.1 reader
sub make_reader {
	my $ido=shift;
	my $server=$ido->[server_];
	\my $rbuf=\$ido->[rbuf_];
	\my $fh=\$ido->[fh_];
	sub {

	}
}

#cancel existing read watcher
# create a new watcher with the passed sub (created beforehand)
# push to the reader_stack
sub push_reader {
	my ($self,$sub)=@_;
	$self->[rw_]=undef;
	$self->[rw_]=AE::io $self->[fh_],0,$sub;
	push @{$self->[read_stack_]},$sub;
	#trigger reader if read buffer is not empty

}
# cancel existing read watcher
# create new watcher from top of stack
# pop the stack
sub pop_reader {
	my $self=@_[0];
	$self->[rw_]=undef;
	$self->[rw_]=AE::io $self->[fh_],0, pop @{$self->[read_stack_]};
}

#readers need to be created previously, capturing the session and optionally making aliases
#to session variables for better performance

1;
