use strict;
use warnings;
package uSAC::HTTP::Constants;

use Export::These;

# Constants for accessing main message variables
use constant::more
    ROUTE=>0,
    REX=>1,
    IN_HEADER=>2,
    HI=>2,

    #HEADER=>3,
    OUT_HEADER=>3,
    HO=>3,

    PAYLOAD=>4,
    CB=>5,
    CRLF=>"\015\012"
;

use Export::These qw<ROUTE REX IN_HEADER OUT_HEADER PAYLOAD CB CRLF>;



# Constants for mode of server/client/none
use constant::more qw<MODE_NONE=0 MODE_SERVER MODE_CLIENT>;
use Export::These qw<MODE_NONE MODE_SERVER MODE_CLIENT>;

1;
