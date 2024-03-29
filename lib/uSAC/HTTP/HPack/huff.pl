#!/usr/bin/env perl
use Data::Dumper;
use feature ":all";
no warnings "experimental";

#outputs perl code/structures from huffman table
#stores codes in symbol indexed array
my @codes;

while(<>){
	if(
		/\(\s*(\d+)\)\s+[^\s]+\s+([^\s]+)\s+\[\s*(\d+)\]/
	){
		#print "Symbol $1, hex $2, len $3\n";
		$codes[$1]=[$1,$3,hex($2)<<(32-$3)];
	}

}
#say Dumper @codes;

#sort by bits
my @sorted= sort { $a->[2] <=> $b->[2] } @codes;
#say Dumper \@sorted;


sub decode_huffman32 {
	\my @table=$_[0];
	#Padd string to multiple of 4 bytes
	my $len=length $_[1];
	my $rem=$len%4;
	if($rem){
		$_[1].=\x00 x (4-$rem);
	}
	$len=length $_[1];
	my $pos=0;
	my $acc=0;
	my $result="";
	my $present_bits;
	my $holding;
	my $shift=32;
	my $mask=0xFFFFFFFF;
	my $holding_bits=0;
	my $acc_bits=0;


	while($pos<$len){
		say "";
		#load more data if holding is empty
		unless($holding_bits){
			say "loading more data";
			$holding=unpack "x[$pos]N", $_[1];
			$holding_bits=32;
			$pos+=4;
			say "loaded Holding: ", unpack "B*",pack "N*", $holding;	
		}

		if($shift>$holding_bits){
			#shift what we can
			say "Clamping shift";
			$shift=$holding_bits;
		}
		my $temp=32-$shift;
		say "Holding: ", unpack "B*",pack "N*", $holding;	
		$acc=$acc | $holding>>$temp;
		$acc_bits+=$shift;
		$holding_bits-=$shift;
		say "after shift: acc_bits: $acc_bits  holding_bits: $holding_bits";
		say "Acc: ", unpack "B*",pack "N*", $acc;	

		if($acc_bits<30){
			#max symbol length not achieved. so redo
			redo;
		}
		say "about to perform search on acc: ", unpack "B*", pack "N*", $acc;
		#test $acc agains table of codes
		for my $entry (@table) {
			my $matcher=$entry->[2];
			my $mask= ~(0xFFFFFFFF>>($entry->[1]));
		
			if($entry->[0]==49){
				say "matcher for 49: ", unpack "B*", pack "N*",$matcher;
				say "bits for 49: ", $entry->[1];
			}
			my $macc= ($acc & $mask);

			#say "mask: ", unpack "B*", pack "N*",$mask;
				#say "macc: ", unpack "B*", pack "N*",$macc;
				#say "test: ", unpack "B*", pack "N*",$entry->[2];
				#say "macc: $macc test: ", $entry->[2];
				#say $macc==$entry->[2];
			if( ($macc == $entry->[2])){
				say "found ", Dumper $entry;
				return $result if $entry->[0] ==256;
				$result.=$entry->[0];	
				$acc&= 0xFFFFFFFF>>$entry->[1];
				$acc<<=$entry->[1];	#shift to align msb in acc
				say "After match and shift";
				say "Acc: ", unpack "B*",pack "N*", $acc;	

				$shift=$entry->[1];
				$acc_bits-=$shift;
				last;
			}
		}
	}
}
sub encode_huffman32 {
	my $acc=0;
	my $bits=0;
	my $pos=0;
	my $len=length $_[1];

	while($pos<$len){
		my @octets=unpack "x[$pos]C4", $_[1];
		$pos+=4;
		#lookup bits
		for my $octet (@octets){
			my $entry=$codes[$octet];
			my $remaining=32-$bits;	
			if($entry->[1]>$remaining){
				$acc|=$entry->[2]>>$bits;#<<$remaining;
				$result.=$acc;
				$acc=0;
			}

			my $shift=32-$bits-$entry->[1];
			$acc|=$entry->[0]<<$shift;
			$bits+=$entry->[1];
		}
	}
}

my $data=pack "B*", "00001111111111111111111111111111111";

#$data=encode_huffman32 \@sorted, "Encode this string";



# my $data=pack "B*", "00001000010000100001000010000100001111111111111111111111111111111";
say "data len: ", length $data;
say Dumper unpack "B*", $data;
decode_huffman32 \@sorted, $data;

