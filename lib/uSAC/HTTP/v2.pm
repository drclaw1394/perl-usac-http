package uSAC::HTTP::v2;
use strict;
use warnings;
use feature qw<say refaliasing>;
no warnings "experimental";
use Exporter 'import';
my @frame_names=map "FRAME_$_", qw(
  DATA
  HEADERS
  PRIORITY
  RST_STREAM
  SETTINGS
  PUSH_PROMISE
  PING
  GOAWAY
  WINDOW_UPDATE
  CONTINUATION
  )
;
my @flag_names=map "FLAG_$_", qw(

  PING_ACK
  END_STREAM	        
  END_HEADERS
  PADDED
  PRIORITY 
);


my @decode_names=qw(
  parse_frames
);

our @EXPORT_OK=(
  @frame_names,
  @flag_names,
  "encode_frames",
  "decode_frames"

);

our @EXPORT=();

our %EXPORT_TAGS=(
  "constants"=>[@frame_names,@flag_names],
  "decode"=>["decode_frames"],
  "encode"=>["encode_frames"]
);
#Framing support for http2
#
#####################################################################
# +-----------------------------------------------+                 #
# |                 Length (24)                   |                 #
# +---------------+---------------+---------------+                 #
# |   Type (8)    |   Flags (8)   |                                 #
# +-+-------------+---------------+-------------------------------+ #
# |R|                 Stream Identifier (31)                      | #
# +=+=============================================================+ #
# |                   Frame Payload (0...)                      ... #
# +---------------------------------------------------------------+ #
#####################################################################
#Values from RFC7540

#frame types
use constant {
  FRAME_DATA		      =>0x00,
  FRAME_HEADERS		    =>0x01,
  FRAME_PRIORITY	    =>0x02,
  FRAME_RST_STREAM	  =>0x03,
  FRAME_SETTINGS	    =>0x04,
  FRAME_PUSH_PROMISE	=>0x05,
  FRAME_PING		      =>0x06,
  FRAME_GOAWAY		    =>0x07,
  FRAME_WINDOW_UPDATE	=>0x08,
  FRAME_CONTINUATION	=>0x09,
	};


#Flags
use constant {
  FLAG_PING_ACK		        =>0x01,
  FLAG_END_STREAM	        =>0x01,
  FLAG_END_HEADERS	      =>0x04,
  FLAG_PADDED		          =>0x08,
  FLAG_PRIORITY	          =>0x20,


};

#Error codes
use constant {
  ERROR_NO_ERROR		        =>0x00,
  ERROR_PROTOCOL_ERROR		  =>0x01,
  ERROR_INTERNAL_ERROR		  =>0x02,
  ERROR_FLOW_CONTROL_ERROR	=>0x03,
  ERROR_SETTINGS_TIMEROUT	  =>0x04,
  ERROR_STREAM_CLOSED		    =>0x05,
  ERROR_FRAME_SIZE_ERROR	  =>0x06,
  ERROR_REFUSED_STREAM		  =>0x07,
  ERROR_CANCEL			        =>0x08,
  ERROR_COMPRESSION_ERROR	  =>0x09,
  ERROR_CONNECT_ERROR		    =>0x0a,
  ERROR_ENHANCE_YOUR_CLAIM	=>0x0b,
  ERROR_INADEQUATE_SECURITY	=>0x0c,
  ERROR_HTTP_1_1_REQUIRED	  =>0x0d,
};

	#Settings
use constant {
  SETTINGS_HEADER_TABLE_SIZE	    =>0x01,
  SETTINGS_ENABLE_PUSH		        =>0x02,
  SETTINGS_MAX_CONCURRENT_STREAMS =>0x03,
  SETTINGS_INITIAL_WINDOW_SIZE	  =>0x04,
  SETTINGS_MAX_FRAME_SIZE		      =>0x05,
  SETTINGS_MAX_HEADER_LIST_SIZE   =>0x06,
};


#Preface
use constant CLIENT_PREFACE=>pack "H*","0x505249202a20485454502f322e300d0a0d0a534d0d0a0d0a";


use constant STATIC_FRAME_PING=> pack "NCNa64",(8<<8)|FRAME_PING, 0, map int(rand(256)), 1..8;

use constant PAD=>pack "a256", "";

my $len;
my $pad;
my $priority;
my $out="";

sub encode_frames {
  $out="";
  for \my @f(@_){
    if($f[0] == FRAME_DATA){
      $pad=($f[1]&FLAG_PADDED);
      say "PAD: $pad, padded flag:".FLAG_PADDED;
      $len=length($f[4]) + ($pad && ($f[3]+1));
      $out.=pack "NCN", ($len<<8)|FRAME_DATA, $f[1], 0x7FFFFFFF & $f[2];
      if($pad){
        $out.=pack "C", $f[3];
        $out.=$f[4];
        $out.=substr(PAD, 0, $f[3])
      }
      else{
        $out.=$f[4];
      }
      say join ", ",@f;
      sleep 1;
    }

    elsif($f[0] == FRAME_HEADERS){
      $pad=($f[1]&FLAG_PADDED);
      $priority=($f[1]&FLAG_PRIORITY);
      say ("Pad : $pad, priority: ".($priority&&(5)));
      $len=(length($f[7])+($pad&&($f[3]+1))+($priority&&5));
      say "LENGTH $len";

      $out.=pack "NCN",
      ($len<<8)|FRAME_HEADERS,  #length (including padding) and type
      $f[1],                    #flags
      0x7FFFFFFF & $f[2]; 		            # Streamid

      if($pad and $priority){
        $out.=pack "CNC", $f[3], (($f[5]&0x7FFFFFFF)|($f[4]<<31)), $f[6];
        $out.=$f[7];
        $out.=substr PAD, 0, $f[3];

      }
      elsif($pad){
        $out.=pack "C", $f[3];
        $out.=$f[7];
        $out.=substr PAD, 0, $f[3];
      }
      elsif($priority){
        $out.=pack "NC", (($f[5]&0x7FFFFFFF)|($f[4]<<31)), $f[6];
        $out.=$f[7];
      }
      else {
        $out.=$f[7];
      }
    }

    elsif($f[0] == FRAME_PRIORITY){
      $len=5;
      $out.=pack "NCNNC",
        ($len<<8)|FRAME_PRIORITY,  #length (5) and type
        0,                          #flags
        (0x7FFFFFFF & $f[2]), 		            # Streamid
        (($f[4]&0x7FFFFFFF)|($f[3]<<31)), # Exlusive, stream_dep
        $f[5];    #Weight	
    }
    elsif($f[0] == FRAME_RST_STREAM){
      $len=4;
      $out.=pack "NCNN",
        ($len<<8)|FRAME_RST_STREAM,  #length (4) and type
        0,                          #flags
        (0x7FFFFFFF & $f[2]), 		            # Streamid
        $f[3]     # Error code

    }
    elsif($f[0] == FRAME_SETTINGS){
      $len=(@f-3)*3;  # key is 2 bytes, value is 4 bytes, 6 bytes per pair
      $out.=pack "NCN(nN)*",
        ($len<<8)|FRAME_SETTINGS,  
        $f[1],
        $f[2]&0x7FFFFFFF,
        @f[3..$#f]                    # remaining k,v pairs
    }
    elsif($f[0]  == FRAME_PUSH_PROMISE){
      $pad=($f[1]&FLAG_PADDED);
      $len=length($f[5])+($pad&&($f[3]+1))+4;
      $out.=pack "NCN",
        ($len<<8)|FRAME_PUSH_PROMISE,  
        $f[1],                          #flags
        0x7FFFFFFF & $f[2]; 		            # Streamid
      if($pad){
        $out.=pack "CN", $f[3], $f[4];
        $out.=$f[5];
        $out.=substr PAD, 0 ,$f[3];
      }
      else {
        $out.=pack "N", $f[4];
        $out.=$f[5];
      }
    }
    elsif($f[0] == FRAME_PING){
      $out.=pack "NCNa8", (8<<8)|FRAME_PING, $f[1], 0, $f[3];
    }
    elsif($f[0] == FRAME_GOAWAY){
      $len=(length($f[5])+8);
      $out.=pack "NCNNN",
        ($len<<8)|FRAME_GOAWAY,  #length and type
        $f[1],                    # flags
        0x7FFFFFFF & $f[2], 		            # Streamid

        $f[3],  #last stream
        $f[4];  # error code

      $out.=$f[5];
    }
    elsif($f[0] == FRAME_WINDOW_UPDATE){
      $out.=pack "NCNN", 
        (4<<8)|FRAME_WINDOW_UPDATE, 
        $f[1],
        0x7FFFFFFF & $f[2], 		            # Streamid
        0x7FFFFFFF & $f[3];      #Size increment
    }
    elsif($f[0] == FRAME_CONTINUATION){
      $len=length($f[3]);
      $out.=pack "NCN", 
          ($len<<8)|FRAME_CONTINUATION, 
          $f[1],
          0x7FFFFFFF & $f[2]; 		            # Streamid
      $out.=$f[3];
    }
  }
  $out;
}


use enum ("PARSE_HEAD=0", "PARSE_PAYLOAD");
my $state=PARSE_HEAD;
my $offset=0;
my $length;
my $flags;
my $stream_id;
my $type;

sub decode_frames {
  my @frames;
  \my $buf=\$_[0];
  while($buf){
    if($state == PARSE_HEAD){
      # Finish parsing if partial header
      last if length ($buf)<9;

      ($length, $flags, $stream_id)=unpack "NCN", substr $buf, 0, 9, "";	#includes type byte
      $type=($length&0xFF);
      $length>>=8;
      $stream_id&=0x7FFFFFFF;

      say "length $length, type: $type, flags $flags, stream $stream_id";
      $state=PARSE_PAYLOAD;
    }

    elsif($state == PARSE_PAYLOAD){
      #payload is not present fully. try again later
      last if(length($buf)<$length);
      
      # Ok we can parse a frame here
      my @frame=($type, $flags, $stream_id);


      #decode based on frame type
      if($type == FRAME_DATA){

        my $pad=($flags & FLAG_PADDED);
        my $head_len=0;
        if($pad){

          $pad=unpack "C", substr $buf, 0, 1, "";
          $head_len++;
          push @frame, $pad, substr $buf, 0, $length-$head_len, "";
          substr($frame[-1], -$pad)="";
        }
        else {
          push @frame, $pad, substr $buf, 0, $length-$head_len, "";
        }
        push @frames, \@frame;
      }

      elsif($type == FRAME_HEADERS){
        my $pad=($flags&FLAG_PADDED);
        my $priority=($flags&FLAG_PRIORITY);
        my $head_len=0;

        if($pad){
          ($pad)=unpack "C", substr $buf, 0, 1, ""; # unpack padding length
          $head_len++;
        }

        push @frame, $pad;

        if($priority){
          $head_len+=5;
          # exclusive, stream_dep, and weight befor
          my ($stream_dep, $weight)=unpack "NC", substr $buf,0,5, "";
          my $exclusive=(0x80000000 & $stream_dep)>>31;
          $stream_dep&=0x7FFFFFFF;

          my $frag=substr $buf, 0, $length-$head_len, "";
          substr($frag,-$pad)="" if $pad;
          push @frame, $exclusive, $stream_dep, $weight, $frag;
        }
        else {
          my $frag=substr $buf, 0, $length-$head_len, "";
          substr($frag,-$pad)="" if $pad;
          push @frame, 0, 0, 0, $frag;
        }
        push @frames, \@frame;      
      }

      elsif($type == FRAME_PRIORITY){
        my ($stream_dep, $weight)=unpack "NC", substr $buf, 0, $length, "";
        my $exclusive=(0x80000000 & $stream_dep)>>31;
        $stream_dep&=0x7FFFFFFF;
        push @frame, $exclusive, $stream_dep, $weight;
        push @frames, \@frame;
      }
      elsif($type == FRAME_RST_STREAM){
        my ($error)=unpack "N", substr $buf,0,$length, "";
        push @frame, $error;
        push @frames, \@frame;

      }
      elsif($type == FRAME_SETTINGS){
        say "Settings";
        my @kv=unpack "(nN)*", substr $buf, 0, $length, "";
        push @frame, @kv;
        push @frames, \@frame;
      }
      elsif($type == FRAME_PUSH_PROMISE){
        my $pad=($flags&FLAG_PADDED);
        my $head_len=0;
        my $dep_stream;
        if($pad){
          ($pad,$dep_stream)=unpack "CN", substr $buf, 0, 5, "";
          $head_len+=5;
        }
        else {
          ($dep_stream)=unpack "N", substr $buf, 0, 4, "";
          $head_len+=4;
        }
        my $frag=substr $buf, 0, $length-$head_len, "";
        substr($frag, -$pad)="" if $pad;
        push @frame, $pad, $dep_stream, $frag;
        push @frames, \@frame;
      }
      elsif($type == FRAME_PING){
        #TODO ensure stream id is 0
        push @frame, substr $buf, 0, $length, "";
        push @frames, \@frame;
      }
      elsif($type == FRAME_GOAWAY){
        #TODO ensure stream id is 0
        my ($last, $error)=unpack "NN", substr $buf, 0, 8, "";
        push @frame, $last, $error;
        push @frame, substr $buf,0, $length-8, "";
        push @frames, \@frame;
      }
      elsif($type == FRAME_WINDOW_UPDATE){
        my ($inc)=unpack "N", substr $buf, 0, $length, "";
        push @frame, $inc;
        push @frames, \@frame;
      }
      elsif($type == FRAME_WINDOW_UPDATE){
        push @frame, substr $buf, 0, $length, "";
        push @frames, \@frame;
      }


      elsif($type == FRAME_CONTINUATION){
        #NO such frame type
        push @frame, substr $buf,0, $length, "";
        push @frames, \@frame;
      }
      else {
        say "NO SUCH FRAME";
      }

      # Set state to header parsing
      $state= PARSE_HEAD;
    }
  }
  @frames;
}


use enum qw<CON_STATE_DISCONNECTED CON_STATE_PREFACE CONSTATE_FRAMES>;
#Create a reader for a session
sub server_reader {
  my $state;
  $state=CON_STATE_DISCONNECTED;
  sub {
    while($buf){
      if($state == CON_STATE_DISCONNECTED){
        # Freshly connected tcp transport
        $state=CON_STATE_PREFACE;
      }
      elsif($state == CON_STATE_PREFACE){
        # TCP transport is estabilished, 
        # if(server ){
        #  write settings frame
        #  }
        # else{
        #    #client
        #   write preface
        #   write settings frame
        #   $state= CON_STATE_FRAMES;
        #
        # }
      }
      elsif($state == CON_STATE_FRAMES){
        #Decode frames incomming.
        #If new stream ids, create a new rex and add to context.
      }
    }

      
  }
}
1;
