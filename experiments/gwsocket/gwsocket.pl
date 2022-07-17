#!/usr/bin/env perl
#
use Data::Dumper;

use Log::ger;
use Log::ger::Output "Screen";
use Log::OK {
	lvl=>"warn",
	opt=>"verbose"
};
Log::ger::Util::set_level Log::OK::LEVEL;

use uSAC::HTTP;
use uSAC::HTTP::Middleware qw<log_simple>;
use uSAC::HTTP::Server::WS;

use uSAC::IO;
use constant ENABLE=>1;

my $server;$server=usac_server{
	usac_listen no_hosts=>1, "0.0.0.0:9090";
	usac_middleware log_simple;

	usac_route GET=>"/ws"=>usac_websocket sub {
		my $ws=shift;
		my $state=0;	#idle, connecting, connected,

		my @queue;
		my $sreader;
		my $swriter;
		my $writer;
		my $socket;
		my $rand=rand 10;
		say "RANDOM: $rand";
		$ws->on_connect=sub {
			$state=1;
			#attempt to open a new connection to the specified host
			#when this succeeds, set the on me
			connect_inet $ws, "localhost", 8081, sub {
				say "CONNECTED TO REMOTE HOST";
				#connected to remote host
				 (undef, $socket)=@_;
				$sreader=uSAC::SReader->new(undef,$socket)->start;
				$sreader->on_read=sub {
					say "ON READ FROM REMOTE";
					$ws->send_text_message($rand.$_[1]);$_[1]="";
				};
				$sreader->on_error=$sreader->on_eof=sub {
					say "ON READ ERROR FROM REMOTE";
					$ws->close;
					$sreader->pause;
					$swriter->pause;
					close $socket;
				};
				$swriter=uSAC::SWriter->new(undef, $socket);;
				$writer=$swriter->writer;
				$state=2;

				for (@queue){
					#write 
					$writer->($_);
				}
				@queue=();
			},
			sub {
				#Error connecting to remote host
				say "COULD NOT CONNECT TO HOST";
				$ws->close;
			}
		};

		$ws->on_message=sub {
			if($state==2){
				#write
				$writer->("$rand $_[2]");
			}
			elsif($state==1){
				#queue data
				push @queue, $_[2];
			}

		};
		$ws->on_error=$ws->on_close=sub {
			#close tcp connection
			if($socket){
				$sreader->pause;
				$swriter->pause;
				close $socket;
			}

		};
		#create a socket connection to a host
	};

	usac_route GET=>"/form1"=>sub {
		#render a form
		my $form=qq|
		<html>
		<body>
			<form action="/form1" method="post" enctype="multipart/form-data">
				<input type="hidden" name="token" value="hello"></input>
				<input type="text" name="field1"></input>
				<input type="file" name="field2"></input>
				<input type="submit" name="submit">
			</form>
		</body>
		</html>
		|;
		rex_write @_, HTTP_OK,[], $form;
		
	};

	usac_route POST=>"/form1"=>usac_form_slurp
		dir=>usac_path(root=>usac_dirname, "uploads"),
		sub{
		my ($matcher, $rex, $data, $headers, $end)=@_;
		say Dumper $data;
		rex_write $matcher, $rex,  HTTP_OK, [], "GOT A FORM";
		
	};

	my $static_path=usac_path root=>usac_dirname, "static";
	
	usac_route GET=>"/hot/$File_Path"=>		usac_static_content "Hello there";

	usac_route GET=>"/$File_Path"=>			usac_file_under $static_path;

	usac_route GET=>"/$Dir_Path"=>			usac_file_under indexes=>[qw<index.html>],  $static_path;

	usac_route [qw<POST PUT>]=>"/upload"=>
		usac_data_slurp mime=>"text/plain", byte_limit=>4096*1024,
			dir=>usac_path(root=>usac_dirname, "uploads"),
			sub {
				my ($matcher, $rex, $data, $headers, $last)=@_;
				say Dumper $headers;
				rex_write $matcher, $rex, HTTP_OK, [], "sdf";
			};

	usac_route [qw<POST PUT>]=>"/multi"=>
		usac_multipart_slurp byte_limit=>4096*1024,
			dir=>usac_path(root=>usac_dirname, "uploads"),
			sub {
				my ($matcher, $rex, $data, $headers, $last)=@_;
				say Dumper $data;
				rex_write $matcher, $rex, HTTP_OK, [], "sdf";
			};

	usac_route [qw<POST PUT>]=>"/urlencoded"=>
		usac_urlencoded_slurp byte_limit=>4096*1024, 
			dir=>usac_path(root=>usac_dirname, "uploads"),
			sub {
				my ($matcher, $rex, $data, $headers, $last)=@_;
				say Dumper $data;
				rex_write $matcher, $rex, HTTP_OK, [], "sdf";
			};
};

$server->run;
__DATA__
