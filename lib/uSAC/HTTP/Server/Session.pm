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
use enum ( "id_=0" ,qw<fh_ closeme_ rw_ rbuf_ ww_ wbuf_ left_ read_ write_ request_count_ server_ read_stack_ on_body_>);

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

#raw writer. 
sub make_writer{
	#take a session and alias the variables to lexicals
	my $ido=shift;
	my $server=$ido->[server_];
	\my $wbuf=\$ido->[wbuf_];
	\my $fh=\$ido->[fh_];
	

	sub {
		\my $buf=\$_[0];	#give the input a name

		if ( $wbuf ) {
			#$ido->[closeme_] and return warn "Write ($buf) called while connection close was enqueued at @{[ (caller)[1,2] ]}";
			${ $wbuf } .= defined $buf ? $buf : return $ido->[closeme_] = 1;
			return;
		}
		elsif ( !defined $buf ) { return drop($ido); }

		##############################################################################################
		# $ido->[fh_] or return do {                                                                 #
		#         warn "Lost filehandle while trying to send ".length($buf)." data for $ido->[id_]"; #
		#         drop($ido,"No filehandle");                                                        #
		#         ();                                                                                #
		# };                                                                                         #
		##############################################################################################

		my $w = syswrite( $fh, $buf );
		if ($w == length $buf) {
			# ok;
			#say Dumper $ido;
			if( $ido->[closeme_] ) { drop $ido};
		}
		elsif (defined $w) {
			$wbuf = substr($buf,$w);
			$ido->[ww_] = AE::io $fh, 1, sub {
				$ido or return;
				$w = syswrite( $fh, $wbuf );
				if ($w == length $wbuf) {
					undef $ido->[ww_];
					if( $ido->[closeme_] ) { drop($ido); }
				}
				elsif (defined $w) {
					$wbuf= substr( $wbuf, $w );
				}
				else { return drop( $ido, "$!"); }
			};
		}
		else { return drop($ido, "$!"); }
	};

}

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
