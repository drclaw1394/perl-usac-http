use feature "say";
use strict;
use warnings;
package uSAC::HTTP::Constants;


use constant::more {
    ROUTE=>0,
    REX=>1,

    #CODE=>2,
    IN_HEADER=>2,

    HEADER=>3,
    OUT_HEADER=>3,

    PAYLOAD=>4,
    CB=>5,
    CRLF=>"\015\012"

};

use Exporter "import";

our @EXPORT_OK=qw<ROUTE REX IN_HEADER OUT_HEADER HEADER PAYLOAD CB CRLF>;
our @EXPORT=@EXPORT_OK;
1;
