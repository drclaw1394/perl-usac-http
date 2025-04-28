#!/usr/bin/env perl
use Data::Dumper;

use feature ":all";
no warnings "experimental";

use uSAC::IO;

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

#sort by bits
my @sorted= sort { $a->[2] <=> $b->[2] } @codes;


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
		asay "";
		#load more data if holding is empty
		unless($holding_bits){
			asay "loading more data";
			$holding=unpack "x[$pos]N", $_[1];
			$holding_bits=32;
			$pos+=4;
			asay "loaded Holding: ", unpack "B*",pack "N*", $holding;	
		}

		if($shift>$holding_bits){
			#shift what we can
			asay "Clamping shift";
			$shift=$holding_bits;
		}
		my $temp=32-$shift;
		asay "Holding: ", unpack "B*",pack "N*", $holding;	
		$acc=$acc | $holding>>$temp;
		$acc_bits+=$shift;
		$holding_bits-=$shift;
		asay "after shift: acc_bits: $acc_bits  holding_bits: $holding_bits";
		asay "Acc: ", unpack "B*",pack "N*", $acc;	

		if($acc_bits<30){
			#max symbol length not achieved. so redo
			redo;
		}
		asay "about to perform search on acc: ", unpack "B*", pack "N*", $acc;
		#test $acc agains table of codes
		for my $entry (@table) {
			my $matcher=$entry->[2];
			my $mask= ~(0xFFFFFFFF>>($entry->[1]));
		
			if($entry->[0]==49){
				asay "matcher for 49: ", unpack "B*", pack "N*",$matcher;
				asay "bits for 49: ", $entry->[1];
			}
			my $macc= ($acc & $mask);

			if( ($macc == $entry->[2])){
				asay "found ", Dumper $entry;
				return $result if $entry->[0] ==256;
				$result.=$entry->[0];	
				$acc&= 0xFFFFFFFF>>$entry->[1];
				$acc<<=$entry->[1];	#shift to align msb in acc
				asay "After match and shift";
				asay "Acc: ", unpack "B*",pack "N*", $acc;	

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
asay "data len: ", length $data;
asay Dumper unpack "B*", $data;
decode_huffman32 \@sorted, $data;

