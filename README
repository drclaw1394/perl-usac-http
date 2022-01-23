# NAME

uSAC::HTTP  - uSAC HTTP Server (and client eventually)

# DESCRIPTION

uSAC::HTTP is a web framework/web server implementing HTTP/1.1. It utilises
persistant connections, a fast dispatching system and aliasing  to achieve solid
performance in vanilla Perl.  It is implemented using:

```
    AnyEvent IO watchers
    uSAC::SIO for Stream reading and writing 
    uSAC::MIME for mime type database
```

It implements a 'declarative', config file like, way of defining a web
server/framework, allowing single file and multifile applications to be
developed. 

Docuemtnation is scant at the moment, as it isn't quote ready for prime time.

# Programming Style

The idea is OO heavy code is used during initialisation, while a more
functional approach is used during runtime. This saves on wasting time on
method lookups when you already know what you want.

In this spirit, setup code is prefixed with `usac_`. These subroutines
generally return another subroutine which is actually executed during runtime.

For example `usac_file_under` takes a directory as an argument and returns the
sub which is called as the endpoint of a route which will serve static files
from that directory

# TODO

List features
Fix documentation
Add cookbook
Add benchmarks
...
