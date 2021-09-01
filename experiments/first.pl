use warnings;
use strict;
use feature "refaliasing";
no warnings "experimental";
use List::Util qw<first>;
use List::MoreUtils qw<first_index>;
use Benchmark qw<cmpthese>;
use Data::Dumper;

use feature ":all";
my @data=map { join "", map { chr(ord('a')+rand(26))} 0..rand(26) } 1..100;
local $,=", ";
#say @data;
#my @re=(qr/.*c/, qr/dsv/, qr/erw/);


my $dispatcher;
my %count;
my @table=(
	[qr/this/=> sub { 
			$count{this}++;
			#say "matched this ($1) and context is:", Dumper $_[0];1
		},0],
	[qr/that/=> sub {
			$count{that}++;
			#say "matched that ($1)";1
		},0],
	[qr/another/=> sub {
			$count{another}++;
			#say "matched that ($1)";1
		},0],
	[qr/word/=> sub {
			$count{word}++;
			#say "matched that ($1)";1
		},0],
);
my @table1=@table;
my @table2=@table;
my @table3=@table;


sub dispatchLoop {
	my ($table,$dut,$ctx)=@_;
	for(0..@table-1){
		if($dut=~ /($table[$_][0])/){
			$table[$_][2]++;
			return $table[$_][1]($ctx);	#call the dispatch
		}

			#returns sub ref, but no access to captures

	}
	undef;
}
sub dispatchFixed {
	my ($table, $dut, $ctx)=@_;
	\my @t=$table;
	given($dut){
		when(/($t[0][0])/){
			$t[0][2]++;		#update hit counter
			$t[0][1]->($ctx);	#execute. Return code indicates if the match is to be cached
			
		}
		when(/($t[1][0])/){
			$t[1][2]++;		#update hit counter
			$t[1][1]->($ctx);	#execute. Return code indicates if the match is to be cached
		}
		when(/($t[2][0])/){
			$t[2][2]++;		#update hit counter
			$t[2][1]->($ctx);	#execute. Return code indicates if the match is to be cached
		}
		when(/($t[3][0])/){
			$t[3][2]++;		#update hit counter
			$t[3][1]->($ctx);	#execute. Return code indicates if the match is to be cached
		}
		default {

		}
	}

}
sub dispatchFixed2{
	my ($table, $dut, $ctx)=@_;
	\my @t=$table;
	my $entry;
	given($dut){

		$entry=$t[0];
		when(/($entry->[0])/){
			$entry->[2]++;		#update hit counter
			$entry->[1]->($ctx);	#execute. Return code indicates if the match is to be cached
			
		}
		$entry=$t[1];
		when(/($entry->[0])/){
			$entry->[2]++;		#update hit counter
			$entry->[1]->($ctx);	#execute. Return code indicates if the match is to be cached
		}
		$entry=$t[2];
		when(/($entry->[0])/){
			$entry->[2]++;		#update hit counter
			$entry->[1]->($ctx);	#execute. Return code indicates if the match is to be cached
		}
		$entry=$t[3];
		when(/($entry->[0])/){
			$entry->[2]++;		#update hit counter
			$entry->[1]->($ctx);	#execute. Return code indicates if the match is to be cached
		}
		default {

		}
	}

}
sub dispatchCached{
	my ($table, $cache, $dut, $ctx)=@_;
	\my @t=$table;
	given($cache->{$dut}){
		when(defined){
			#do the actual match
			/$_->[0]/;
			$_->[2]++;		#update hit counter
			$_->[1]->($ctx);	#execute. Return code indicates if the match is to be cached
			return;
		}
		default {
		}
	}
	my $entry;
	given($dut){

		$entry=$t[0];
		when(/($entry->[0])/){
			$entry->[2]++;		#update hit counter
			$cache->{$dut}=$entry;
			$entry->[1]->($ctx);	#execute. Return code indicates if the match is to be cached
			
		}
		$entry=$t[1];
		when(/($entry->[0])/){
			$entry->[2]++;		#update hit counter
			$cache->{$dut}=$entry;
			$entry->[1]->($ctx);	#execute. Return code indicates if the match is to be cached
		}
		$entry=$t[2];
		when(/($entry->[0])/){
			$entry->[2]++;		#update hit counter
			$cache->{$dut}=$entry;
			$entry->[1]->($ctx);	#execute. Return code indicates if the match is to be cached
		}
		$entry=$t[3];
		when(/($entry->[0])/){
			$entry->[2]++;		#update hit counter
			$cache->{$dut}=$entry;
			$entry->[1]->($ctx);	#execute. Return code indicates if the match is to be cached
		}
		default {

		}
	}

}


sub buildDispatch {
	\my @table=shift;
	my $d="sub {\n";
	$d.='my ($table,$dut,$ctx)=@_;'."\n";
	$d.='\my @t=$table;'."\n".' given ($dut) {'."\n";
	for (0..@table-1) {
		my $pre='$t['.$_.']';

		$d.='when (/('.$pre."[0])/){\n";
		$d.=$pre."[2]++;\n";
		$d.=$pre.'[1]->($ctx);'."\n";
		$d.="}\n";
	}
	$d.="default {\n";
	$d.="}\n";
	$d.="}\n}\n";
	eval($d);
}

sub buildCachedDispatch {
	\my @table=shift;
	my $d="sub {\n";
	$d.='my ($table,$cache,$dut,$ctx)=@_;'."\n";
	$d.='\my @t=$table;'."\n";
	$d.='given($cache->{$dut}){
		when(defined){
			$_->[2]++;		#update hit counter
			/$_->[0]/;
			$_->[1]->($ctx);	#execute. Return code indicates if the match is to be cached
			return;
		}
		default {
		}
	}';
	$d.=' given ($dut) {'."\n";


	for (0..@table-1) {
		my $pre='$t['.$_.']';

		$d.='when (/('.$pre."[0])/){\n";
		$d.=$pre."[2]++;\n";
		$d.='$cache->{$dut}='.$pre.";\n";
		$d.=$pre.'[1]->($ctx);'."\n";
		$d.="}\n";
	}
	$d.="default {\n";
	$d.="}\n";
	$d.="}\n}\n";
	say $d;
	eval($d);
}

sub optimise {
	\my @t=shift;	#let sort work inplace
	@t=sort {$b->[2] <=> $a->[2]} @t;
}
sub resetCounters {
	\my @t=shift;
	for (@t){
		say "reset ",Dumper $_;
		$_->[2]=0;
	}
}

#########################################
# dispatch(\@table, "this", [qw<asd>]); #
# dispatch(\@table, "that");            #
# dispatch(\@table, "that");            #
#                                       #
# say Dumper \@table;                   #
# say Dumper optimise \@table;          #
# resetCounters \@table;                #
# say Dumper \@table;                   #
#                                       #
# exit;                                 #
#                                       #
#########################################
#
my $dynamic=buildDispatch \@table;
my %cache;
my $dynamicCached=buildCachedDispatch \@table;
my %dynamicCache;

say $!;
say $@;
say Dumper $dynamic;
my @words=qw<this that another word>;
my @samples=map { $words[rand 4] } 0..1000000;
cmpthese(scalar(@samples),
	{"loop"=> sub {
			state $i;;
			dispatchLoop \@table1,$samples[$i++],[];
			#optimise \@table if $i%10000;
		},
		"regex"=>sub {
			state $i;;
			dispatchFixed \@table2,$samples[$i++],[];
			#optimise \@table if $i%10000;

		},
		"regex2"=>sub {
			state $i;;
			dispatchFixed2 \@table2,$samples[$i++],[];
			#optimise \@table if $i%10000;

		},
		"cached"=>sub {
			state $i;;
			dispatchCached \@table2,\%cache,$samples[$i++],[];
			#optimise \@table if $i%10000;

		},
		"dynamic"=> sub {
			state $i;
			$dynamic->(\@table3,$samples[$i++],[]);
                        ###########################################
                        # if($i%10000){                           #
                        #         optimise \@table;               #
                        #         $dynamic=buildDispatch \@table; #
                        # }                                       #
                        ###########################################
		},

		"dynamicCached"=> sub {
			state $i;
			$dynamicCached->(\@table3,\%dynamicCache,$samples[$i++],[]);
		}
		}

	);
say Dumper \%count;
