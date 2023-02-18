use feature "say";
use strict;
use warnings;
package uSAC::HTTP::Constants;


use constant::more {
    ROUTE=>0,
    REX=>1,
    CODE=>2,
    HEADER=>3,
    PAYLOAD=>4,
    CB=>5,
    CRLF=>"\015\012"

};

########################
# use constant::more { #
#     PAYLOAD=>0,      #
#     CB=>1,           #
#     ROUTE=>2,        #
#     REX=>3,          #
#     CODE=>4,         #
#     HEADER=>5,       #
#     CRLF=>"\015\012" #
#                      #
# };                   #
########################
use Exporter "import";

our @EXPORT_OK=qw<ROUTE REX CODE HEADER PAYLOAD CB CRLF>;
our @EXPORT=@EXPORT_OK;
#############################################################
# sub import {                                              #
#         my $caller=caller;                                #
#         my $i=0;                                          #
#         for(qw<ROUTE REX CODE HEADER PAYLOAD CB>){        #
#                 no strict "refs";                         #
#                 my $name='*'.$caller."::".$_;             #
#                 my $a=$i;                                 #
#                 *{$name}=sub {$a};#\${'uSAC::HTTP::'.$_}; #
#                 $i++;                                     #
#         }                                                 #
#                                                           #
# }                                                         #
#############################################################
1;
