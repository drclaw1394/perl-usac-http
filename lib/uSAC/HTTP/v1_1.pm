package uSAC::HTTP::v1_1;
use common::sense;
use feature "refaliasing";
no warnings "experimental";
#each subroutine excepts a session argument
##make http1.1 default writer

use uSAC::HTTP::Server::Session;
use uSAC::HTTP::Server;

#base level  tcp writer.
#Handles the event loop and writing to file handle
sub make_writer{
	#take a session and alias the variables to lexicals
	my $ido=shift;
	my $stackPos=shift;
	my $server=$ido->[uSAC::HTTP::Server::Session::server_];
	\my $wbuf=\$ido->[uSAC::HTTP::Server::Session::wbuf_];
	\my $fh=\$ido->[uSAC::HTTP::Server::Session::fh_];
	

	sub {
		\my $buf=\$_[0];	#give the input a name

		if ( $wbuf ) {
			#$ido->[closeme_] and return warn "Write ($buf) called while connection close was enqueued at @{[ (caller)[1,2] ]}";
			${ $wbuf } .= defined $buf ? $buf : return $ido->[uSAC::HTTP::Server::Session::closeme_] = 1;
			return;
		}
		elsif ( !defined $buf ) { return $ido->drop(); }

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
			if( $ido->[uSAC::HTTP::Server::Session::closeme_] ) { $ido->drop};
		}
		elsif (defined $w) {
			$wbuf = substr($buf,$w);
			$ido->[uSAC::HTTP::Server::Session::ww_] = AE::io $fh, 1, sub {
				$ido or return;
				$w = syswrite( $fh, $wbuf );
				if ($w == length $wbuf) {
					undef $ido->[uSAC::HTTP::Server::Session::ww_];
					if( $ido->[uSAC::HTTP::Server::Session::closeme_] ) { $ido->drop(); }
				}
				elsif (defined $w) {
					$wbuf= substr( $wbuf, $w );
				}
				else { return $ido->drop( "$!"); }
			};
		}
		else { return $ido->drop("$!"); }
	};

}

sub make_post_reader {
        ###################################
        # my $session=shift;              #
        # my $server=$session->[server_]; #
        # \my $rbuf=\$session->[rbuf_];   #
        # \my $fh=\$session->[fh_];       #
        ###################################
	sub {
		#we have a content length so only read that many bytes
		#If any content encoding is present then also decode
		#If the data size is expected to be larger than limit, write to file
		#
		#Otherwise store data in stream attribute of the rex

	}
}

sub make_post_gzip_reader {

}

sub make_post_deflate_reader {

}

sub make_chuncked_reader {
	#similar to post
	#once the data size is over a certain limit, save to disk
}


#Writers

sub make_identity_writer {
	#default already on the 1.1 stack
}

sub make_gzip_writer {
	#optional writer to push on the session?
}

sub make_compress_writer {

}
sub make_deflate_writer {

}

#write chunkheaders with the configured chunk size
sub make_chunked_identity_writer {
	#options include chunk size;
	#only written out when buffered data that of chunk (possibly use writev?)
	#when undef is provided, what ever left is written as a single chunk
	#
	##call the writer at one level lower in the stack
}

sub make_chunked_compress_writer {

}

sub make_chunked_deflate_writer {
	#as above but additionally compress with gzip
	#This should be an auto load sub (probably). Reduce the memory required to load
	#the compression modules (large)
}

sub make_chunked_gzip_writer {

}


1;
