package uSAC::HTTP::Site;
use v5.36;
use Log::ger;
use Log::OK;


use feature ":all";
no warnings "experimental";

use Object::Pad;

# Fields for a route structure
# Site is the site object
# inner/outer/error head are the middleware heads
# counter is hit counter
# table is the host table associated with the route
#
use Import::These qw<uSAC:: Util ::HTTP:: Route Constants>;

# Fields for a host structure. contains the lookup table (hustle::Table), the cache for the table, the dispatcher for the table.
#
# Also  for client side has the serialised address, quest queue, idle pool and active count
#
use constant::more qw<
  HOST_TABLE=0
  HOST_TABLE_CACHE
  HOST_TABLE_DISPATCH
  ADDR
  REQ_QUEUE
  IDLE_POOL
  ACTIVE_COUNT

  TLS_INFO
  >;

use uSAC::IO;
use uSAC::TLS ":all";

use Exception::Class::Base;

use URI;
	
use Export::These qw(
  $Path
  $Comp
  $File_Path
  $Dir_Path
  $Any_Method
);


use Import::These qw<uSAC::HTTP:: Code Method Header Rex Constants>;

use uSAC::HTTP::v1_1_Reader;      #TODO: this will be dynamically linked in
use Sub::Middler;


class uSAC::HTTP::Site;

no warnings "experimental";
field $_staged_routes     :reader;
field $_parent_site       :mutator :param=undef;
field $_id                :mutator :param=undef;
field $_prefix            :mutator :param =undef;
field $_host              :reader :param =[];
field $_error_uris        :param={};
field $_delegate          :param=undef;
field $_innerware         :mutator :param=[];
field $_outerware         :mutator :param=[];
field $_errorware         :mutator :param=[];
field $_mode              :mutator :param=1; #none 0, server 1, client 2,

field $_mime_default      :mutator;  #Default mime type
field $_mime_db           :mutator;   #the usac::mime object
field $_mime_lookup       :mutator;   # lookup table (hash) of 
                                # extension to mime type
field $_unsupported;
field $_built_label;
field $_label;

#field $_protocols;      # Hash of Proto name to API

field $_secrets        :mutator; # Hash table of host(no port num) to tls structures


my @supported_methods=qw<HEAD GET PUT POST OPTIONS PATCH DELETE UPDATE TRACE>;

our $ANY_METH=qr/^(?:GET|POST|HEAD|PUT|UPDATE|DELETE|PATCH|OPTIONS|TRACE) /;
our $ANY_URL=qr/.*+ /;
our $ANY_VERS=qr/HTTP.*$/;

our $Any_Method	=qr/(?:GET|POST|HEAD|PUT|UPDATE|DELETE|PATCH|OPTIONS|TRACE)/;

our $Method=		qr{^([^ ]+)};

#NOTE Path matching tests for a preceeding /
#
our $Path=		qr{(?:<=[/])([^?]*)};		#Remainder of path components  in request line
our $File_Path=		qr{(?:<=[/])([^?]++)(?<![/])};#[^/?](?:$|[?])};
our $Dir_Path=		qr{(?:<=[/])([^?]*+)(?<=[/])};

#NOTE Comp matching only matches between slashes
#
our $Comp=		qr{(?:[^/?]+)};		#Path component
our $Decimal=   qr{(?:\d+)};    #Decimal Integer
our $Word=      qr{(?:\w+)};    #Word

my $id=0;


BUILD{
  # Ensure a site ID
  $_id//=$id++;

  # ... and a prefix
  $_prefix//="";

  # No staged routes at this point
  $_staged_routes//=[];

  # Only add delegate if specified
  $self->add_delegate($_delegate) if $_delegate;

  # Normalize host
  if(defined($_host) and ref $_host ne "ARRAY"){
    $_host=[$_host];
  }
  else {
    $_host=[];
  }

  ####################################################################
  # $_protocols//={};                                                #
  # # Add default protocol if no protocol namespace/object specified #
  # unless(%$_protocols) {                                           #
  #    $self->add_protocol("uSAC::HTTP::v1_1_Reader");               #
  # }                                                                #
  ####################################################################


}

method _inner_dispatch {
    # 0 server
    # Server mode uses rex_write as the end/dispatch for inner ware chain
    # This gives an opertunity to to set some important values particular to server side
    #
    Log::OK::TRACE and log_trace __PACKAGE__. " end is server ".join ", ", caller;
    #\&rex_write;
    undef;
}

method _error_dispatch {
  uSAC::HTTP::v1_1_Reader::make_error;
}

method rebuild_routes {
  my $result;
  no strict "refs";
  for my $r ($_staged_routes->@*){

    my $ref =ref $r;

    if($r isa __PACKAGE__){
      $r->rebuild_routes; # Recurse down
    }
    elsif (($ref  ne "ARRAY" and $ref ne "HASH") or %{$r."::"}){
      # Other object or namespace
      $_delegate=$r;    # update the active delegate for implicit routes
      $self->_delegate($r);
    }
    else {
      # Assume "normal" route
      $result=$self->_add_route(@$r);
      die Exception::Class::Base->throw("Route Addition: attempt to use unsupported method. Must use explicit method with paths not starting with /") unless $result;
    }
  }
  $self;
}

#Adds routes to a servers dispatch table
#A handler is added for a successful match of method type
#Any methods not supported are also added by with a 405 return
#middleware can be specified. it is appended to the common middleware for the site
#if prefixing is used, an automatic stripper middleware is installed. The original uri is
#available in the rex object.
#If the server is configured for virtual hosts, the matching mechanism also includes the host matcher
#specified in the site initialization
#
method _add_route {
  local $,=" ";
  my $method_matcher=shift;
  my $path_matcher=shift;

  return unless $method_matcher;

  # Dead horse stripper is always the first
  #
  unshift @_, uhm_dead_horse_stripper(prefix=>$self->built_prefix);


  # Fix up and break out middleware
  #
  \my (@inner, @outer, @error)=$self->_wrap_middleware(@_);
  

  # Innerware run form parent to child to route in
  # the order of listing. Splice after dead horse
  #
  #unshift @inner, $self->construct_innerware;
  splice @inner, 1, 0, $self->construct_innerware;

  # Outerware is in reverse order
  #unshift @outer, $self->construct_outerware;
  splice @outer, 1, 0, $self->construct_outerware;
  @outer=reverse @outer;


  #unshift @error, $self->construct_errorware;
  splice @error, 1, 0, $self->construct_errorware;

  my $end=$self->_inner_dispatch;

  my $static_headers=$self->find_root->static_headers;

  #TODO: Need to rework this for other HTTP versions
  #       SHOULD use the parse/serialize stored in the session

  my $serialize=uSAC::HTTP::v1_1_Reader::make_serialize mode=>$self->find_root->mode, static_headers=>$static_headers;

  my $outer_head;
  if(@outer){
    my $middler=Sub::Middler->new();
    $middler->register($_) for(@outer);

    $outer_head=$middler->link($serialize, site=>$self); #TODO: Pass in the site or the route as a
                                            # Configuration option
                                            # Allows middleware to adjust for client
                                            # or server
  }
  else {
    $outer_head=$serialize;
  }


  my $inner_head;
  if(@inner){
    my $middler=Sub::Middler->new();
    for(@inner){
      $middler->register($_);
    }
    #$inner_head=$middler->link($end, site=>$self);
    $inner_head=$middler->link($end//$outer_head, site=>$self);
  }
  else{
    $inner_head=$end;
  }

  my $err=$self->_error_dispatch;

  my $error_head;
  if(@error){
    my $middler=Sub::Middler->new();
    for(@error){
      $middler->register($_);
    }
    $error_head=$middler->link($err, site=>$self);
  }
  else{
    $error_head=$err;
  }

  my @hosts;

  @hosts=$self->build_hosts;	#List of hosts (as urls) 

  push @hosts, "*.*" unless @hosts;


  #Log::OK::DEBUG and log_debug __PACKAGE__. " Hosts for route ".join ", ", @hosts;
  my $pm;

  for my $uri (@hosts){
    my $host;
    if(ref $uri){
      $host=$uri->host;
      if($uri->port!=80 or $uri->port !=443){
        $host.=":".$uri->port;
      }
    }
    else {
      $host=$uri;	#match all
    }

    # 
    # Fix the path matcher to a regex if the method matcher 
    # is a regex.
    #
    if(ref($method_matcher) eq "Regexp"
        and defined $path_matcher
        and ref($path_matcher) ne "Regexp"){
      # Force pathmatcher to re if method  matcher is an re
      $path_matcher=qr{$path_matcher} ;

    }
    my ($matcher, $type, $path_matcher)=$self->__adjust_matcher($host, $method_matcher, $path_matcher);

    # Create a route structure
    my @route;
    $route[ROUTE_SITE]=$self;
    $route[ROUTE_INNER_HEAD]=$inner_head;
    $route[ROUTE_OUTER_HEAD]=$outer_head;
    $route[ROUTE_ERROR_HEAD]=$error_head;
    $route[ROUTE_SERIALIZE]=$serialize;
    $route[ROUTE_COUNTER]=0;
    $route[ROUTE_TABLE]=undef;

    unless(ref $path_matcher){
      # Allows middleware like static files serving to strip the entire prefix
      # INCLUDING the last part of the route if it is a basic string
      $route[ROUTE_PATH]=$self->built_prefix.($path_matcher//"");
    }
    else{
      # Last part is a regex, so only include the prefix of the site. A  manual prefix 
      $route[ROUTE_PATH]=$self->built_prefix;
    }

    # Actually add the route to the server/client
    $self->find_root->add_host_end_point($host, $matcher, \@route, $type);
    last unless defined $matcher;

  }
  return 1;
}

# Returns a matcher and a type suitable for using in a hustle::table
method __adjust_matcher {
  my ($host, $method_matcher, $path_matcher)=@_;
  my $matcher;
  my $type;
    # $host, @matcher (for method), $path_matcher
  local $"=",";
  my $bp=$self->built_prefix;                                      #
  Log::OK::TRACE and log_trace "$host=>$method_matcher ";
  #test if $path_matcher is a regex

  if(ref($path_matcher) eq "Regexp"){
    $type=undef;
    #$pm=$path_matcher;
    $matcher=qr{^$method_matcher $bp$path_matcher};
  }
  elsif(!defined $path_matcher){
    $type=undef;
    #$pm=$path_matcher;
    $matcher=undef;
    #$matcher=qr{$method_matcher $bp$path_matcher};
  }
  elsif($path_matcher =~ /\$$/){
    #$pm=substr $path_matcher, 0, -1;
    Log::OK::TRACE and log_trace "Exact match";
    $type="exact";
    #my $pm=
    $path_matcher =~ s/\$$//;
    $matcher="$method_matcher $bp$path_matcher";
  }
  else {
    $type="begin";
    $matcher="$method_matcher $bp$path_matcher";
  }
  ($matcher, $type, $path_matcher);
}

# Fix middle described only as a sub
# Resolve delegate-by-name middleware specs
#
method _wrap_middleware {
  Log::OK::TRACE and log_trace __PACKAGE__. " _wrap_middleware";
#my $self=shift;
  my @inner;
  my @outer;
  my @error;

  while(@_){
    #$end=$_;
    local $_=shift;

    # If the element is a code ref it is innerware ONLY
    #
    if(ref eq "CODE"){
      Log::OK::TRACE and log_trace __PACKAGE__. " Plain singlar CODE ref. Wrapping as Innerware";
      # A straight code reference does not have any calls to 'next'.
      # wrap it in one
      my $target=$_; #User supplied sub
      
      my $sub=sub {  #Sub which will be called during linking
        my $next=shift;
        sub {        #wrapper sub (inner middleware)
          # if target returns true, will automatically call next
          &$target and &$next;
        }
      };
      push @inner, $sub;
    }

    # If its an array ref, then it might contain both inner
    # and outerware and possible an error handler
    elsif(ref eq "ARRAY"){
      Log::OK::TRACE and log_trace __PACKAGE__. " ARRAY ref. Unwrap as inner and outerware";
      #check at least for one code ref
      if(ref($_->[0]) ne "CODE"){
        $_->[0]=sub { state $next=shift};  #Force short circuit
      }

      if(ref($_->[1]) ne "CODE"){
        $_->[1]=sub { state $next=shift};  #Force short circuit
      }
      if(ref($_->[2]) ne "CODE"){
        $_->[2]=sub { state $next=shift};  #Force short circuit
      }

      push @inner, $_->[0];
      push @outer, $_->[1];
      push @error, $_->[2];

    }
    elsif(!defined){
      die Exception::Class::Base->throw("Undefined Middleware attempted");
    }
    elsif (ref eq "" ){
      # Scalar used as a method name. Call method on delegate
      # and unshift the result to be processed
      # TODO: need a iteration limit here...
      die Exception::Class::Base->throw("No delegate set for site. Cannot call method by name: $_")unless $_delegate;
        

      # Use postfix notation to access either a package or object method 
      #
      my $string;
      my @pre;
      my $hook;
      try {
        $hook=$_delegate->middleware_hook;
      }
      catch($e){
        Log::OK::WARN and log_warn $e;
      }

      if($hook){
        unless(ref $hook eq "CODE"){
          my $msg="$_delegate->middleware_hook must return a subroutine reference";
          log_fatal  $msg;
          die $msg;
        }
        $hook->($self);
      }

      if($@){
        Log::OK::TRACE and log_trace "No middleware method/sub in delegate... ignoring";
      }


      $string='$_delegate->'.s/\$$//r;

      my @a=eval $string;
      die Exception::Class::Base->throw("Could not run $_delegate with method $_. $@") if $@;
      unshift @_, @pre, @a;
    }
    else {
      #Ignore anything else
      #TODO: check of PSGI middleware and wrap
    }
  }

  # Return references
  (\@inner, \@outer, \@error);

}



method site_url {
	my $url=$self->built_prefix;
	if($_[0]//""){
		return "$url$_[0]";
	}
	$url
}

method built_prefix {
	my $parent_prefix;
	if($self->parent_site){
		$parent_prefix=$self->parent_site->built_prefix;
	}
	else {
		$parent_prefix="";

	}

  $parent_prefix.$_prefix;
}


method build_hosts {
	my $parent=$self;#$_[0];
	my @hosts;
	while($parent) {
		push @hosts, $parent->host->@*;	
		last if @hosts;		#Stop if next level specified a host
		$parent=$parent->parent_site;
	}
	@hosts;
}

#find the root and unshift middlewares along the way
method construct_innerware {
	my $parent=$self;#$_[0];
	my @middleware;
	while($parent){
		Log::OK::TRACE and log_trace "Middleware from $parent";
		Log::OK::TRACE and log_trace "Parent_site ". ($parent->parent_site//"");
		unshift @middleware, @{$parent->innerware//[]};
		$parent=$parent->parent_site;
	}
	@middleware;
}

method construct_outerware {
	my $parent=$self;#$_[0];
	my @outerware;
	while($parent){
		unshift @outerware, @{$parent->outerware//[]};
		$parent=$parent->parent_site;
	}
	@outerware;
}

method construct_errorware {
	my $parent=$self;
	my @errorware;
	while($parent){
		unshift @errorware, @{$parent->errorware//[]};
		$parent=$parent->parent_site;
	}
	@errorware;
}

method built_label {
	my $parent_label;
	if($self->parent_site){
		$parent_label=$self->parent_site->built_label;
	}
	else {
		$parent_label="";

	}
  #$_built_label//($self->set_built_prefix($parent_label.$self->build_label));
  $parent_label.$_label;
}

#Resolves the ext to mime table the hierarchy. Checks self first, then parent
method resolve_mime_lookup {
	my $parent=$self;
	my $db;;
	while($parent) {
		$db=$parent->mime_db;
		last if $db;
		$parent=$parent->parent_site;
	}
		
	$db?($db->index)[0]:{};
}

#Resolves the default mime in the hierarchy. Checks self first, then parent
method resolve_mime_default {
	my $parent=$self;
	my $default;
	while($parent) {
		$default=$parent->mime_default;
		last if $default;
		$parent=$parent->parent_site;
	}
		
	$default?$default:"applcation/octet-stream";
}

# Add a the callee to the supplied object
method add_to {
  my $parent=pop;
	my $root=$self->find_root;
  $self->mode=$root->mode;
  $self->parent_site=$parent;
  $parent->add_route($self);
  $self;

}

# Add a site to the callee object
method add_site {
  for my $site(@_){
    my $root=$self->find_root;
    $site->mode=$root->mode;
    $site->parent_site=$self;
    $self->add_route($site);
  }
  $self;
}



method child_site {
  my $root=$self->find_root;
  my $child=uSAC::HTTP::Site->new(parent_site=> $self);
}

method find_root {
	my $parent=$self;

	while($parent->parent_site){
		$parent=$parent->parent_site;
	}
	$parent;
}

sub supported_methods {
  @supported_methods;
}

method default_method {
  "GET";
}

sub any_method { $Any_Method; }

method _method_match_check{
    my $result;
    my ($matcher)=@_;

    if(ref($matcher) eq "ARRAY"){
      # Convert from array or methods to a alterate regex
      $matcher= "(?:".join("|", @$matcher).")"; 
      $matcher=qr{$matcher};
    }

    $result =$matcher if grep /$matcher/, $self->supported_methods;
    $result;
}

# Add a delegate. This inserts the delegate into the staged routes list.
# At rebuild time, the route list is processed sequentially. So multiple delegates
# can be added to a site.
# The  LATEST delegate is used for implicit routing
#
method add_delegate {
  no strict "refs";
  for(@_){
    # Add the items as a delegate if it is a ref or the name space exists
    push @$_staged_routes, $_ if ref $_ or  %{$_."::"}; # Copy to staging
  }
}

method add_route {
  my $del_meth;

  my $ref=ref $_[0];

  # Direct push if another site object
  if($_[0] isa uSAC::HTTP::Site){
    push @$_staged_routes, $_[0]; # Copy to staging
    return $self;
  }

  # If the first argument is a simple scalar, test if it is a method
  # name. If it IS NOT a method name, we assume it it path and unshift
  # the default method to the route
  if(ref $_[0] eq ""){
    # Inject default method immediately if no method provided
    #
      my $meth=$_[0]//"";
      unless($meth and grep /$meth/, $self->supported_methods){
        unshift @_, $self->default_method;
      }
  }

  

  try {
    # Adjust for 1 and two argument short hand
    #
    if(@_== 2 and ref($_[1]) eq ""){
      #
      # Only 1 argument (path). Implict method and route to delegate
      #
      #single argument and its a scalar
      # Duplicate the argument as it will be the name of a method to call on the delegate
      #
      $del_meth=$_[1];
      unless($del_meth){
        $del_meth="__";
      }
      else {
        $del_meth=join "", map {"_${_}_"} split "/", $del_meth, -1;
      }

      push @_, $del_meth;
      push @$_staged_routes, [@_]; # Copy to staging
    }


    elsif(@_ == 2 and ref($_[0]) eq "" and ref($_[1]) eq ""){
        # Two argument , first string is method, second is path
        # implicit route to delegate
        #
        $del_meth=$_[1];
        unless($del_meth){
          $del_meth="__";
        }
        else {
          $del_meth=join "", map {"_${_}_"} split "/", $del_meth, -1;
        }
        #$del_meth=join "", map {"_${_}_"} split "/", $del_meth, -1;

        push @_, $del_meth;
        unshift @_, $self->default_method if $_[0] =~ m|^/| or $_[0] eq "";
        push @$_staged_routes, [@_]; # Copy to staging
    }
    
    elsif(@_ == 2 and ref($_[0]) eq "ARRAY" and ref($_[1]) eq ""){
        # Two argument ,first is HTTP method array, second is path
        # implicit route to delegate
        #
        my $a=shift;

        $a= "(?:".join("|", @$a).")";

        #Test the methods actually match somthing

        $a=qr{$a};
        my $b=shift;
        $del_meth=$b;   # The path is the basis for implicit method
        unless($del_meth){
          $del_meth="__";
        }
        else {
          $del_meth=join "", map {"_${_}_"} split "/", $del_meth, -1;
        }
        #$del_meth=join "", map {"_${_}_"} split "/", $del_meth, -1;

        $b=qr{$b}; #if defined $b;
        unshift @_, $a, $b, $del_meth;
        push @$_staged_routes, [@_]; # Copy to staging

    }

    elsif(@_ == 2 and ref($_[0]) eq "RegExp" and ref($_[1]) eq ""){
        # Two argument ,first is HTTP method regex, second is path scalar
        # implicit route to delegate
        #
        my $a=shift;

        #$a= "(?:".join("|", @$a).")";

        #Test the methods actually match somthing

        #$a=qr{$a};
        
        my $b=shift;

        $del_meth=$b;   # The path is the basis for implicit method
        unless($del_meth){
          $del_meth="__";
        }
        else {
          $del_meth=join "", map {"_${_}_"} split "/", $del_meth, -1;
        }
        #$del_meth=join "", map {"_${_}_"} split "/", $del_meth, -1;

        $b=qr{$b}; #if defined $b;
        unshift @_, $a, $b, $del_meth;
        push @$_staged_routes, [@_]; # Copy to staging
    }

    else {
      # Long form processing
      #
      #

      die Exception::Class::Base->throw("Route Addition: a route needs at least two parameters (path, middleware, ...) or (method, path, middleware ...")
      unless @_>=2;



      if(!defined($_[0])){
        # 
        # Sets the default for the host
        #
        shift; unshift @_, $self->any_method, undef;
        push @$_staged_routes, [@_]; # Copy to staging
      }


      elsif(ref($_[0]) eq "ARRAY"){
        #
        # Methods specified as an array ref, which will get
        # converted to a regexp
        # Also means the path matcher must also be changed
        #
        my $a=shift;
        #unshift @_, "(?:".join("|", @$a).")";
        $a= "(?:".join("|", @$a).")";

        #Test the methods actually match somthing


        $a=qr{$a};
        my $b=shift;
        my $method=$b;
        $b=qr{$b} if defined $b;
        unshift @_, $a, $b;

        if(@_ == 2){
          #Only method type and path specified.
          $method=~s|^/||g;
          $method=~s|/|__|g;
          push @_, $method;
        }

        push @$_staged_routes, [@_]; # Copy to staging
      }


      elsif(ref($_[0]) eq "Regexp"){
        if(@_>=3){
          #method and path matcher specified
          push @$_staged_routes, [@_]; # Copy to staging
        }
        else {
          #Path matcher is a regex
          unshift @_, "GET";
          push @$_staged_routes, [@_]; # Copy to staging
        }
      }
      elsif($_[0] eq ""){
        # Explicit matching for site prefix
        unshift @_, $self->default_method;
        push @$_staged_routes, [@_]; # Copy to staging
      }
      else{
        # method, url and middleware specified
        push @$_staged_routes, [@_]; # Copy to staging
      }

    }

  }
  catch($e){
    #my $trace=Devel::StackTrace->new(skip_frames=>1); # Capture the stack frames from user call
    require Error::Show;
    log_fatal Error::Show::context(message=>$e, frames=>[$e->trace->frames]);
    exit;
    #$e->throw;
  }
  $self;    #Chaining
}


# Set the delegate for the site. Can be an
#   object reference
#   Package name (ie My::Package)
#   CWD Relative or absolute path  to file to require
#   reference to scalar relative-to-caller path to require
# Note does not attempt to require a Package if the package has any keys
# present
method _delegate {
  $_delegate=$_[0];
  my $caller=$_[1]//[caller];
  if(ref $_delegate eq "SCALAR"){
    #resolve relative-to-caller- path
    $_delegate=path $_delegate, $caller;
  }
    
  unless(ref $_delegate){
    # If delegate is not a reference, assume it is a package name. Check the package exists
    #
    no strict "refs";
    die Exception::Class::Base->throw("Delegate package $_delegate not found. Do you need ro require it?") unless (%{$_delegate."::"});
  }

  
  local $uSAC::HTTP::Site=$self;
  # Attempt to auto import any route chains
  try {
      #my $string;
      #$string="$_delegate->_auto";
      #eval "$string";
      $_delegate->auto_route_hook->($self);
  }
  catch($e){
    no strict "refs";
    warn "Delegate has no valid auto_route_hook. ignoring; $e"
    #Exception::Class::Base->throw("Delegate  has no import $e");
  }
  $self;
}

# Options could include CA and server key paths
# Host here include the port number for direct matching in http
# However host certificates do not refernce port number. Certs and keys are then
# located in another structure?
#
method add_host {
	my $host=pop;	#Content is the last item
	my %options=@_;

	my @uri;
	if(ref($host) eq "ARRAY"){
		@uri= map {URI->new("http://$_")} @$host;
	}
	else{
		@uri= map {URI->new("http://$_")} ($host);
	}
	for(@uri){
		die "Error parsing hosts: $_ " unless ref;
	}
	push $_host->@*, @uri;
}

# Certificates, keys, ca
method add_secret {
  my $host=URI->new(shift);
  my @entries;

  for(@_){
    if(ref  eq "ARRAY"){
      #kv pairs. Assume correct structure
      push @entries, $_;
    }
    else {
      # hash. convert into structure
      for my($k,$v) (%$_){
      
      }
      #push @entries, $_;
    }
  }

  #Process entries
  for(@entries){
    say $host->host;
    $_->[TLS_INFO_HOST]=$host->host;
    $_secrets->{$host}=$_
  }
}



method add_middleware {
  #my %options=@_;
  for my $mw (@_){
    \my (@inner, @outer, @error)=$self->_wrap_middleware($mw);
    push $_innerware->@*, @inner;
    push $_outerware->@*, @outer;
    push $_errorware->@*, @error;
  }
  $self;
}


########## Error handling - server side


method add_error_route {
  #my $self=shift;
	#Force the method to match GET
	unshift @_, "GET";
	$self->add_route(@_);
}


method set_error_page {
  #my $bp=$self->built_prefix;

	for my($k, $v)(@_){
		$_error_uris->{$k}=$v;#"$bp$v";
	}

  $self;
}

method error_uris {
  $_error_uris;
}


method set_mime_default {
  #my $self=shift;
	my $default=pop;
	my %options=@_;
	$self->mime_default=$default//"application/octet-stream";

}

method set_mime_db {
#my $self=shift;
	my $db=pop;
	my %options=@_;
	$self->mime_db=$db;
	($self->mime_lookup)=$self->mime_db->index;
}

sub uhm_dead_horse_stripper {
  my %options=@_;
  
	my $len=length ($options{prefix}//"");;
	my $inner=sub {
		my $inner_next=shift;
    my $index=shift;
    my %options=@_;
    $inner_next;
    ###########################################################################################
    #             sub {                                                                       #
    #   Log::OK::TRACE and log_trace "STRIP PREFIX MIDDLEWARE";                               #
    #                                                                                         #
    #   if($_[OUT_HEADER]){                                                                   #
    #     ###########################################                                         #
    #     # use Data::Dump::Color;                  #                                         #
    #     # dd $_[OUT_HEADER];                      #                                         #
    #     # $_[IN_HEADER]{":path_stripped"}=        #                                         #
    #     #   $len                                  #                                         #
    #     #   ?substr($_[IN_HEADER]{":path"}, $len) #                                         #
    #     #   : $_[IN_HEADER]{":path"};             #                                         #
    #     ###########################################                                         #
    #   }                                                                                     #
    #                                                                                         #
    #   &$inner_next; #call the next                                                          #
    #                                                                                         #
    #   #Check the inprogress flag                                                            #
    #   #here we force write unless the rex is in progress                                    #
    #   #Log::OK::WARN and log_warn "REX in progress flag not set!";                          #
    #   ##################################################################################### #
    #   # unless($_[REX][uSAC::HTTP::Rex::in_progress_]){                                   # #
    #   #   Log::OK::TRACE and log_trace "REX not in progress. forcing rex_write/cb=undef"; # #
    #   #   $_[CB]=undef;                                                                   # #
    #   #   return &rex_write;                                                              # #
    #   # }                                                                                 # #
    #   ##################################################################################### #
    #                                                                                         #
    #   Log::OK::TRACE and log_trace "++++++++++++ END STRIP PREFIX";                         #
    #   undef;                                                                                #
    # },                                                                                      #
    ###########################################################################################

	};

  my $outer=sub {
    my ($next ,$index, %options)=@_;
      # This is now the pipeline sequencer
      $next
      ######################################################################
      # sub {                                                              #
      # #my $session=$_[REX][uSAC::HTTP::Rex::session_];                   #
      #   my $seq=$_[REX][uSAC::HTTP::Rex::sequence_];#$session->sequence; #
      #   my $pipeline=$_[REX][uSAC::HTTP::Rex::pipeline_];#$session->rex; #
      #                                                                    #
      #   #say "Session $session";                                         #
      #   #say "seq: $seq";                                                #
      #   #say "Pipeline $pipeline";                                       #
      #                                                                    #
      #   # Save the arguments into partition sequence                     #
      #   if($seq->{$_[REX][uSAC::HTTP::Rex::id_]}){                       #
      #     push $seq->{$_[REX][uSAC::HTTP::Rex::id_]}->@*, \@_;           #
      #                                                                    #
      #                                                                    #
      #     # Use the first rex as key and call middleware                 #
      #     my $rex=$pipeline->[0];                                        #
      #     my $args=shift $seq->{$rex->[uSAC::HTTP::Rex::id_]}->@*;       #
      #     $next->(@$args);                                               #
      #                                                                    #
      #     # If the CB was not set, then that was the end                 #
      #     # of the rex so shift it off                                   #
      #     unless ($args->[CB]){                                          #
      #       shift @$pipeline;                                            #
      #       delete $seq->{$rex->[uSAC::HTTP::Rex::id_]};                 #
      #     }                                                              #
      #   }                                                                #
      #   else {                                                           #
      #     # short cut.                                                   #
      #     shift @$pipeline unless ($_[CB]);                              #
      #     &$next;                                                        #
      #   }                                                                #
      #                                                                    #
      # }                                                                  #
      ######################################################################
  };

  my $error=sub {
    my ($next ,$index, %options)=@_;
    my $site=$options{site};

    if($site->mode==0){
      sub {
        &$next;
      }
    }
    else {
      sub {
      #say "CLIENT error dead horse";
        #say $_[ROUTE][1][ROUTE_TABLE][uSAC::HTTP::Site::ACTIVE_COUNT]--;
        #my($route, $captures)=$entry->[uSAC::HTTP::Site::HOST_TABLE_DISPATCH]("$method $uri");


        &$next;
      }
    }
  };

  [$inner, $outer, $error];
}


method process_cli_options{
  my $options=shift//[];
  say "process cli options in site";
  my $hook;
  try {
    $hook=$_delegate->process_cli_options_hook;
  }
  catch($e){
    Log::OK::DEBUG and log_debug "$e";
  }

  if($hook){
    die "process_cli_options_hook must return a subroutine reference"unless ref $hook eq "CODE";
    $hook->($self, $options);# if $_delegate;
  }

  # Send message down the tree
  for my $r ($self->staged_routes->@*){
    if($r isa __PACKAGE__){
      $r->process_cli_options($options);
    }
  }
  $self;
}

method load {
	my $path=pop;
	my %options=@_;
  $path=path $path, [caller];
	
	$options{package}//=(caller)[0];
	
	#recursivley include files
	if(-d $path){
		#Dir list and contin
    my @files= <"${path}/*">;
    
    ###############################################################
    # opendir(my $dir, $path);                                    #
    # my @files= map "$path/$_" , grep !/^\.{1,2}/, readdir $dir; #
    # #say "files: @files";                                       #
    # closedir $dir;                                              #
    ###############################################################

		for my $file (@files){
      #local $uSAC::HTTP::Site=$self;
			$self->load( %options, $file);
		}
	}
	else{
		#not a dir . do it
		Log::OK::INFO and log_info "Including server script from $path";
    #my $result=
    #eval "require '$path'";
    local $uSAC::HTTP::Site=$self;
    local $@;
    eval { need $path };

    if($@){
      my $error=$@;
      require Error::Show;
      my $context=Error::Show::context($error);
      Log::OK::ERROR and log_error $context;
      #log_error "Could not include file: $@";
      die "Could not include file $path";	
    }
	}
  $self;
}



#########################################################################
# # Protocol support                                                    #
# #                                                                     #
# method add_protocol {                                                 #
#   # key value pair to look up protocol parsing and serializing        #
#   # makers. Associates a namepspace or object and which provides:     #
#   #   protocol_id   =>  return the name/id of the protocol            #
#   #   make_parser   =>  returns a sub which makes a new parser        #
#   #   make_serialize  =>  returns a sub which maskes a new serializer #
#   #   make_error    =>    returns a sub which makes a new error sub   #
#   #                                                                   #
#   # Default is http/1.1                                               #
#   my $ns=shift;                                                       #
#   my $id=$ns->protocol_id;                                            #
#   Log::OK::INFO and log_info "Loading protocol $ns";                  #
#   $_protocols->{$id}=$ns;                                             #
#                                                                       #
# }                                                                     #
#                                                                       #
#########################################################################
# TLS HTTP/1.1 h2
#   Use ALNP for proto selection
#
# HTTP/1.1 h2c
#   HTTP Upgrade mech
#   Must start connection with 1.1
#
# Prior knowlege connection
#   h2c 
#   must start connection with h2c
#
__PACKAGE__;
