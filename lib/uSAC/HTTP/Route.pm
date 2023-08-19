package uSAC::HTTP::Route;

# A route as the first argument of a message is actuall the raw entry inthe
# Hustle::Table lookup. This is an array of [matcher, value, type, default]
#
# The value within that entry is structure defined in this file.
#
# [ site, inner, outer, error, counter, table]
#
# Site:
#   is the site object
#
# inner/outer/error:
#   are the middleware heads
#
# counter:
#   hit counter
#
# table:
#  is the host table associated with the route. This is updated with the last
#  table the route was match from. This is used for retrigger more request in
#  client mode, to the same host if any are queued
#

use enum qw<
  ROUTE_SITE
  ROUTE_INNER_HEAD
  ROUTE_OUTER_HEAD
  ROUTE_ERROR_HEAD
  ROUTE_SERIALIZE
  ROUTE_COUNTER
  ROUTE_TABLE
  ROUTE_PATH
  >;

use Export::These qw<
  ROUTE_SITE
  ROUTE_INNER_HEAD
  ROUTE_OUTER_HEAD
  ROUTE_ERROR_HEAD
  ROUTE_SERIALIZE
  ROUTE_COUNTER
  ROUTE_TABLE
  ROUTE_PATH
>;


1;
