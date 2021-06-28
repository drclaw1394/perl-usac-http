package uSAC::HTTP::v1_1;
#each subroutine excepts a session argument

sub make_post_reader {
	my $session=shift;
	my $server=$session->[server_];
	\my $rbuf=\$session->[rbuf_];
	\my $fh=\$session->[fh_];
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
