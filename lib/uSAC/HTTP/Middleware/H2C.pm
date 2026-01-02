package uSAC::HTTP::Middleware::H2C;

# Middleware to upgrade a http/1.1 connection to http/2.0  h2c (no tls)
#
# The clear text (non encrypted) http/2.0 connection can be established using
# the http/1.1 upgrade mechanism, much like the WebSocket upgrade
#
# For encrypted communictions the negotiation is handle at the TLS/ALNP level
