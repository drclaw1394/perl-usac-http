#!/usr/bin/env perl
use strict;
use warnings;

use feature qw<refaliasing say state switch current_sub>;
no warnings "experimental";
no feature "indirect";

use Data::Dumper;
	my $fork=$ARGV[0]//0;
BEGIN {
	@uSAC::HTTP::Server::Subproducts=("testing/1.2");
}

use uSAC::HTTP;
use uSAC::HTTP::Server;
use uSAC::HTTP::Code qw<:constants>;
use uSAC::HTTP::Method qw<:constants>;
use uSAC::HTTP::Rex;
use uSAC::HTTP::Middleware ":all";
use uSAC::HTTP::Static;


###############################################################################
# given(\%uSAC::HTTP::Session::make_writer_reg){                              #
#         #$_->{http1_1_static_writer}=\&make_static_file_writer;             #
#         $_->{http1_1_chunked_writer}=\&make_chunked_writer;                 #
#         $_->{http1_1_chunked_deflate_writer}=\&make_chunked_deflate_writer; #
# }                                                                           #
# #say "Chunked writer",\&make_chunked_writer;                                #
###############################################################################


my @sys_roots=qw<data>;


my $server = uSAC::HTTP::Server->new(
	host=>"0.0.0.0",
	port=>8080,
	cb=>sub {},
	#enable_hosts=>1
);

my $site1=$server->register_site(
	uSAC::HTTP->new(
		id=>"site1",
		prefix=>	"/some/sub/path", 
		host=>		qr{localhost:8080|127.0.0.1:8080},
		#middleware=>[log_simple]
	)
);

site_route $site1 => 'GET' => '/small$' =>()=>sub{
		state $data="a" x (1024*4);
		#my ($line, $rex)=@_;
		rex_reply_simple @_, HTTP_OK, undef, $data;
		return;	
};

my $chunk_size=1024*4;
site_route $site1=>GET=>'/big$' => sub{
                state $data="a" x (1024*4);
		#my ($line, $rex)=@_;
		my $pos=0;
		#cb simply returns the data chunks to send
		#say @_;	
		my $length=length $data;
		rex_reply_chunked @_, HTTP_OK, undef, sub {
			return unless my $writer=$_[0];		#writer callback
			#return unless $writer;		#exit if error
			
			my $d=substr($data, $pos, $chunk_size);
			$pos+=length $d;
			
			#say "Last: $last";	
			$writer->($d, $pos == $length ? undef :__SUB__);		#callback to this sub
		};
                return;
};

site_route $site1=>qr{GET|HEAD}=>qr{/public$Path}=>(
	#log_simple
        )=>sub {
		send_file_uri_norange @_, $1, 'data';
		return;

};

site_route $site1=>GET=>'.*'=> (log_simple)=>sub {
                rex_reply_simple @_, HTTP_OK, undef, "CATCH ALL FOR SITE 1";
                return;
};


my $site2=$server->register_site(
        uSAC::HTTP->new(
                id=>"site2",
                host=>"localhost:8080|127.0.0.1:8080",
        )
);

site_route $site2=>GET=>'/$'=> (
	#log_simple
)=>uSAC::HTTP::welcome_to_usac;

site_route $site2=>GET=>'/small$'=>sub {
	rex_reply_simple @_, HTTP_OK, undef, "Some small data";return};

#Public files
site_route $site2 => qr{GET|HEAD}=>qr{/public$Path} =>
        (
		#log_simple
        ) =>

        sub {
			
		my $p=$1;
		if(substr($1,-1) eq "/"){
				#if($1=~m|/$|){
			list_dir @_, $p,'data';
		}
		else{
			send_file_uri_norange @_, $p, 'data';
		}
                return;
        };

site_route $site2=>GET=>'.*'=>
        (log_simple)=>
        sub { rex_reply_simple @_, HTTP_OK, undef, "CATCH ALL FOR SITE 2"; return;
        };
$server->run;
