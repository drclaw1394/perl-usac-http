package uSAC::HTTP::CGI;
use strict;
use warnings;
use feature qw<state refaliasing current_sub>;

sub new {

}

#similar to static file module interms of locating files, however executes instead of reading
sub usac_cgi_under {
	#create a new static file object
	my $parent=$_;
	my $root=shift;

	if($root =~ m|^[^/]|){
		#implicit path
		#make path relative to callers file
		$root=dirname((caller)[1])."/".$root;
	}

	#setup the environment for CGI.
	

	my %options=@_;
	$options{mime}=$parent->resolve_mime_lookup;
	$options{default_mime}=$parent->resolve_mime_default;
	my $static=uSAC::HTTP::Static->new(root=>$root,%options);
	#check for mime type in parent 
	my $sfunr=$static->make_send_file_uri_norange();
	my $sfur=$static->make_send_file_uri_range();
	
	#create the sub to use the static files here
	sub {
		#matcher, rex, uri if not in $_
		my $rex=$_[1];
		#my $p=$1;
		my $p;
		if($_[2]){
			$p=$_[2];
			pop;
		}	
		else {
			$p=$1;
		}

    #if($rex->[uSAC::HTTP::Rex::headers_]{RANGE}){
		if($_[IN_HEADER]{range}){
			#send_file_uri_range @_, $p, $root, $cache;
			$sfur->(@_,$p);
			return;
		}
		else{
			#Send normal
			#$static->send_file_uri_norange(@_, $p, $root);
			$sfunr->(@_,$p);
			return;
		}
	}

	
}
1;
