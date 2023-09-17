package uSAC::HTTP::HPack;
use strict;
use warnings;
use feature qw<say switch>;
no warnings "experimental";
use feature qw<say>;

use Data::Dumper;
our %STATIC;
our @STATIC=(
	[0 , 	undef, 				undef],
	[1 , ":authority", 			undef],
	[2 , ":method",				"GET"],
	[3 , ":method",				"POST"],
	[4 , ":path",				"/"],
	[5 , ":path",				"/index.html"],
	[6 , ":scheme",				"http"],
	[7 , ":scheme",				"https"],
	[8 , ":status",				"200"],
	[9 , ":status",				"204"],
	[10, ":status",				"206"],
	[11, ":status",				"304"],
	[12, ":status",				"400"],
	[13, ":status",				"404"],
	[14, ":status",				"500"],
	[15, "accept-charset",			undef],
	[16, "accept-encoding", 		"gzip, deflate"],
	[17, "accept-language",			undef],
	[18, "accept-ranges", 			undef],
	[19, "accept", 				undef],
	[20, "access-control-allow-origin", 	undef],
	[21, "age",				undef],
	[22, "allow",				undef],
	[23, "authorization",			undef],
	[24, "cache-control",			undef],
	[25, "content-disposition",		undef],
	[26, "content-encoding",		undef],
	[27, "content-language",		undef],
	[28, "content-length",			undef],
	[29, "content-location",		undef],
	[30, "content-range",			undef],
	[31, "content-type",			undef],
	[32, "cookie",				undef],
	[33, "date",				undef],
	[34, "etag",				undef],
	[35, "expect",				undef],
	[36, "expires",				undef],
	[37, "from",				undef],
	[38, "host",				undef],
	[39, "if-match",			undef],
	[40, "if-modified-since",		undef],
	[41, "if-none-match",			undef],
	[42, "if-range",			undef],
	[43, "if-unmodified-since",		undef],
	[44, "last-modified",			undef],
	[45, "link",				undef],
	[46, "location",			undef],
	[47, "max-forwards",			undef],
	[48, "proxy-authenticate",		undef],
	[49, "proxy-authorization",		undef],
	[50, "range",				undef],
	[51, "referer",				undef],
	[52, "refresh",				undef],
	[53, "retry-after",			undef],
	[54, "server",				undef],
	[55, "set-cookie",			undef],
	[56, "strict-transport-security",	undef],
	[57, "transfer-encoding",		undef],
	[58, "user-agent",			undef],
	[59, "vary",				undef],
	[60, "via",				undef],
	[61, "www-authenticate",		undef],


);

use constant::more {
		EXISTING=>		0,
		INCREMENT=>		1,
		TABLE_SIZE=>		2,
		NO_INCREMENT=>		3,
		NEVER_INCREMENT=>	4,
	};
use constant::more DYNAMIC_OFFSET=>62;

our @BITS_PRE=(
	7,
	6,
	5,
	4,
	4
);

our @CODES_PRE=(
	0x80,
	0x40,
	0x20,
	0x10,
	0x00
);

our @F_PRE=(
	[7, 0x80],
	[6, 0x40],
	[5, 0x20],
	[4, 0x10],
	[4, 0x00]
);


#our @EXPORT_OK=
use Export::These qw<
encode_integer
decode_integer
encode_string
decode_string
encode_field
decode_field

encode_headers
decode_headers
build_static
	>;
  #our @EXPORT=@EXPORT_OK;
  #
use constant::more ("size_limit_=0",qw<current_size_ dynamic_hash_ dynamic_array_>);



sub new {
	#create a new hpack context, which is a dynamic table
	#
	my $package=shift//__PACKAGE__;
	my $self=[];
	$self->[size_limit_]=4096;
	$self->[current_size_]=0;
	$self->[dynamic_hash_]={};
	$self->[dynamic_array_]=[];
	bless $self, $package;
}
#add dynamic table entry to the start of table list
sub add_entry {
	say "adding entry";
	my $array=$_[0][dynamic_array_];
	my $hash=$_[0][dynamic_hash_];
	#calculate the 'size' of the table with the new field added.
	given($_[1].$_[2]){
		my $new_size=$_[0][current_size_]+length $_;
		while($new_size>$_[0][size_limit_]){
			#need pop off old entries 
			my $e=pop $array->@*;
			my $string=$e->[0].$e->[1];
			delete $hash->{$string};
			$_[0][current_size_]-=length $string;
			$new_size=$_[0][current_size_]+length $_;
		}
		#reindex entries remaining
		$_->[0]++ for ($array->@*);

		#make a key from name and value for hash
		my $ref=[DYNAMIC_OFFSET, $_[1], $_[2]];
		$hash->{$_}=$ref;		#KV 
		$hash->{$_[1]}=$ref;	#K

		#unshift into dynamic table
		unshift $array->@*, $ref;

	
		say Dumper $_[0][dynamic_hash_];
		say Dumper $_[0][dynamic_array_];
	}
}

sub build_static {
	for my $entry (@STATIC){
		next unless $entry->[1];
		#$STATIC{$entry->[1]}=$entry;
		$STATIC{$entry->[1].($entry->[2]//"")}=$entry;# if $entry->[2];
		$STATIC{$entry->[1]}=$entry;
	}
}

#global static table

sub encode_integer {
	use integer;
	my ($value,$bits,$msb)=splice @_, 3;
	my $a=2**$bits-1;
	my @result;
	my $i=0;
	if($value<$a){

		$result[$i++]=($msb & ~$a)|$value;
	}
	else{
		$result[$i++]=($msb & ~$a)|$a;
		$value-=$a;
		while($value>=128){
			$result[$i++]=($value%128)| 128;
			$value/=128;
		}
		$result[$i++]=$value;
	}

	substr($_[1], $_[2])=pack "C*", @result;
	$_[2]+=@result;
	return;
}

#arguments: $data, $offset reference, $other 
#return: prefix, and value
sub decode_integer {
	use integer;
	my ($bits)=splice @_, 3;
	my $mask=2**$bits-1;
	my $result=unpack "x[$_[2]]C", $_[1];
	my $start= ~$mask & $result;
	$result&=$mask;
	my $offset=1;

	if($result==$mask){
		
		#unpack the next 4 bytes	
		
		my $i=1;

		my @data=unpack "C*", substr $_[1], $i, 4;
		my $j=-1;
		do{
			$j++;
			$result+=($data[$j]& 127)*(2**(7*($j)));
			$offset++;

		} while(($data[$j] & 128) ==128);

	}
	$_[2]+=$offset; #update the offset
	$start, $result;
		
}

sub encode_string {
	my ($string, $flag)=splice @_, 3;
	my $len=length $string;
	unless($flag){
		encode_integer @_, $len, 7, $flag;
		substr($_[1], $_[2])=$string;
		$_[2]+=$len;
	}
	else {
		#TODO: huffman
	}

}

sub decode_string {
	push @_, 7;
	my ($flags, $len)=&decode_integer;

	if($flags){
		#huffman encoded
	}
	else {
		#direct octets
		my $a=substr($_[1], $_[2], $len);
		$_[2]+=$len;
		$a;
	}
}


sub encode_field {
	my ($name, $value, $mode)= splice @_, 3;
	my $entry;
	$mode//=INCREMENT;
	given($name.$value){
		$entry=$STATIC{$_}//$_[0][dynamic_hash_]{$_};
	}
	if($mode==EXISTING){
		say "Encoding existing Header";
		return undef unless $entry;
		#Encoder with code
		encode_integer @_, $entry->[0], $F_PRE[$mode]->@*;
		return 1;
	}
	else{
		#need to use a literal value
		my $new_name=$STATIC{$name}//$_[0][dynamic_hash_]{$name};
		say "new name: ", Dumper $new_name;
		if($new_name){
			#name exists. use its code
			encode_integer @_, $new_name->[0],$F_PRE[$mode]->@*;
			encode_string @_, $value, 0;
		}
		else {
			say "Name does not exist: $name";
			#header name not existing encode new new name
			encode_integer @_, 0, $F_PRE[$mode]->@*;
			say "after integer";
			say $name;
			encode_string @_, $name, 0;
			say "after name";
			encode_string @_, $value, 0;
			
			#update the dynamic table
			add_entry $_[0], $name, $value;
		}
	}
}
sub decode_field {
	my $field=$_[1];
	my $offset=$_[2];
	my $byte=unpack "x[$offset]C", $field;
	#$byte&=0xF0;
	if($byte & 0x80){
		#push @_, 7;
		$_[3]=7;
		my ($prefix, $code)=&decode_integer;
		[($STATIC[$code]//$_[0][dynamic_array_][$code])->@[1,2]];
		#test 1 bit pattern
		#Indexed header
	}
	elsif($byte & 0x40){
		$_[3]=6;
		say "INCREMENTAL DECODE";
		my (undef,$code)=&decode_integer;
		say "code is $code";
		if($code){
			#name exists in table
			[($STATIC[$code]//$_[0][dynamic_array_][$code-DYNAMIC_OFFSET])->[1], &decode_string];
		}
		else {
			#name does not exist and we need to prepend it
			[&decode_string, &decode_string];
		}

		#test 2 bit pattern
		#Literal to be indexed
	}
	elsif($byte & 0x20){
		#test 3 bit pattern
		$_[3]=3;
		my (undef, $size)=&decode_integer;
		#adjust table size here
	}
	elsif($byte & 0x10) {
		#test for 4 bit pattern (1)
		$_[3]=4;
		my (undef,$code)=&decode_integer;
		if($code){
			#name exists in table
			[($STATIC[$code]//$_[0][dynamic_array_][$code-DYNAMIC_OFFSET])->[1], &decode_string];
		}
		else {
			#name does not exist, but do not add to table. Proxy
			[&decode_string, &decode_string];
		}

		#test 2 bit pattern
		#Literal to be indexed
	}
	else{
		#last 4 bit pattern 0
		$_[3]=4;
		my (undef,$code)=&decode_integer;
		if($code){
			#name exists in table
			[($STATIC[$code]//$_[0][dynamic_array_][$code-DYNAMIC_OFFSET])->[1], &decode_string];
			#[$STATIC[$code]->[1], &decode_string];
		}
		else {
			#name does not exist, but do not add to table. NOrmal
			[&decode_string, &decode_string];
		}

		#test 2 bit pattern
		#Literal to be indexed
	}
}
sub encode_headers {
	# 0 => ctx,
	# 1 => buffer
	# 2 => offset
	# @* => header pairs
	my $self= $_[0];
	local $,=",";
	for(splice @_, 3){
		say "params", @_;

		encode_field @_, $_->@*;
	}
}
sub decode_headers {
	# 0=> ctx
	# 1=>buffer
	# 2=>offset
	say "Decoding headers";
	while($_[2]<length $_[1]){
		say Dumper &decode_field;
		say "offset : $_[2]";
		say "Length: ", length $_[1];
	}
}


1;
