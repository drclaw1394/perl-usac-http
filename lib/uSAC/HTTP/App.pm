package uSAC::HTTP::App;

# A base for the complete routing, chaing and resource files for a web based app
#
# AN APP HAS A ONE OR MORE URL END POINTS WITH MIDDLEWARE CHAINS
# 
# MIDDLEWARE DOES NOT DEPEND ON A URL ENDPOINT
#
# FRAGMENT is PARTIAL app. It is a perl file which adds url endpoints and chains to a parent site
#
#
# It is a subclass of uSAC::HTTP::Site, so it can be added to a site heriarchy
# Unlike a site, however this is inteneded to wrap up the actual resources on
# the local file system
#
# There can be multiple apps on a server/ heirarachy. Treat as a site, but also
# manage local resources

use Object::Pad;

class uSAC::HTTP::App :isa(uSAC::HTTP::Site);



# routes
# prefixed by site hierrachy

# templates
# Occupies the same name space as other templates and static files under src
# URLTable is shared t


# static files
# Copy files under this to html_root. NOTE these files occupy the same name space as other apps


1;
