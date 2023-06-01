package uSAC::HTTP::v2;
use strict;
use warnings;
use feature qw<say switch>;
no warnings "experimental";
use Exporter 'import';

our @EXPORT_OK=qw<
	serialize_data_frame 
	serialize_priority_frame 
	serialize_reset_stream_frame
	serialize_settings_frame
	serialize_ping_frame
	parse_frame
	>;
our @EXPORT=@EXPORT_OK;

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
  FRAME_GO_AWAY		    =>0x07,
  FRAME_WINDOW_UPDATE	=>0x08,
  FRAME_CONTINUATION	=>0x09,
	};


#Flags
use constant {
  PING		            =>0x01,
  END_STREAM	        =>0x01,
  END_HEADERS	        =>0x04,
  PADDED		          =>0x08,
  PRIORITY	          =>0x20,


};
#Error codes
use constant {
  NO_ERROR		        =>0x00,
  PROTOCOL_ERROR		  =>0x01,
  INTERNAL_ERROR		  =>0x02,
  FLOW_CONTROL_ERROR	=>0x03,
  SETTINGS_TIMEROUT	  =>0x04,
  STREAM_CLOSED		    =>0x05,
  FRAME_SIZE_ERROR	  =>0x06,
  REFUSED_STREAM		  =>0x07,
  CANCEL			        =>0x08,
  COMPRESSION_ERROR	  =>0x09,
  CONNECT_ERROR		    =>0x0a,
  ENHANCE_YOUR_CLAIM	=>0x0b,
  INADEQUATE_SECURITY	=>0x0c,
  HTTP_1_1_REQUIRED	  =>0x0d,
};

	#Settings
use constant {
  HEADER_TABLE_SIZE	  =>0x01,
  ENABLE_PUSH		      =>0x02,
  MAX_CONCURRENT_STREAMS =>0x03,
  INITIAL_WINDOW_SIZE	=>0x04,
  MAX_FRAME_SIZE		  =>0x05,
  MAX_HEADER_LIST_SIZE=>0x06,
};




sub serialize_data_frame {
	#payload octets
	#type
	#flags
	#stream id
	#
	#padding
	#data, pad_len, stream_end, stream_id
	#
	#stream_id,stream_end, data, pad_len
	my ($stream_id, $stream_end, $payload, $pad_len)=@_;
	$pad_len//=0;
	pack "NCNa*",
		((length($payload)+$pad_len)<<8)|FRAME_DATA,		#length and type
		$stream_end|($pad_len>0?PADDED:0),	#flags
		0x7FFFFFFF & $stream_id, 		#streamid
		$payload,				#actual data
		#$pad_len				#pad_len 0s
	;
}

sub serialize_priority_frame {
	#stream_id
	#dependency
	#exclusive
	#weight
	
	pack  "NCNNC", 
		(5<<8)|FRAME_PRIORITY,
		0,
		0x7FFFFFFF & $_[0],
		$_[1] & ($_[2]<<31),
		$_[3]
		;

}

sub serialize_reset_stream_frame {
	#stream_id
	#error code
	pack "NCNN",
		(4<<8) |FRAME_RST_STREAM,	#length and type
		0,			#Flags
		0x7FFFFFFF & $_[0],	#stream id
		$_[1];
		
}

sub serialize_settings_frame {
	#stream, ack_flag, header_list
	my $header_list=$_[2];
	my $format= "NCN(nN)[".@$header_list/2 ."]";
	say $format;
	my $length=16*32*@$header_list/2;
	pack $format, 
		$length<<8|FRAME_SETTINGS,
		$_[1],
		0,	#0x7FFFFFFF & $_[0], #Settings apply to connection not stream
		@$header_list;
}

sub serialize_ping_frame {
	pack "NCNa64",
		(4<<8) |FRAME_PING,	#length and type
		$_[0],			#Flags
		0,			#Connection not stream
		$_[1];			#data

}


sub parse_data_frame {
	
}

sub parse_frame {
  my $frame =shift;
  my ($length, $flags, $stream_id)=unpack "NCN", $frame;	#includes type byte
  my $type=$length&0xFF;
  $length>>=8;
  $stream_id&=0x7FFFFFFF;

  say "length $length, flags $flags, stream $stream_id";

  #decode based on frame type
  for($type){
    when(FRAME_DATA){
      if($flags & PADDED){
        return substr $frame, 10;
      }
      return substr $frame, 9;
    }
    when(FRAME_HEADERS){
    }
    when(FRAME_PRIORITY){
      my ($stream, $weight)=unpack "NC", substr $frame, 9;
      my $exclusive=($stream>>31);
      $stream&=0x7FFFFFFF;
      say "stream $stream, exclusive $exclusive, wieght $weight";
    }
    when(FRAME_RST_STREAM){
      my ($error_code)=unpack "N", substr $frame, 9;
      say "Error code:  $error_code";
    }
    when(FRAME_SETTINGS){
      my @settings=unpack "(nN)*", substr $frame, 9;
      local $,=", ";
      say @settings
    }
    when(FRAME_PUSH_PROMISE){

    }
    when(FRAME_PING){
      my $payload= unpack "a*", substr $frame, 9;
      say $payload;
    }
    when(FRAME_GO_AWAY){
    }
    when(FRAME_WINDOW_UPDATE){
    }
    when(FRAME_CONTINUATION){
    }
    default {
    }
  }
}
1;
