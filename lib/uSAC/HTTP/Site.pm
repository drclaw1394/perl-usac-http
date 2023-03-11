package uSAC::HTTP::Site;
use warnings;
use strict;
use version; our $VERSION=version->declare("v0.0.1");
use feature ":all";
no warnings "experimental";

use Object::Pad;

use enum qw<ROUTE_CTX_SITE ROUTE_CTX_INNER_HEAD ROUTE_CTX_OUTER_HEAD ROUTE_CTX_COUNTER ROUTE_CTX_TABLE>;
use enum ("HOST_TABLE=0", qw<HOST_TABLE_CACHE HOST_TABLE_DISPATCH ADDR REQ_QUEUE IDLE_POOL ACTIVE_COUNT>);


use Log::ger;
use Log::OK;
use Cwd qw<abs_path>;
use File::Spec::Functions;
use Exporter "import";
use uSAC::HTTP::Constants;

use Error::Show;
use Exception::Class::Base;

use URI;

my @redirects=qw<
	usac_redirect_see_other 
	usac_redirect_found
	usac_redirect_temporary
	usac_redirect_not_modified
	usac_redirect_internal
	>;

my @errors=qw<
  usac_catch_route
  usac_error_not_found
	usac_error_page
	usac_error_route
>;	
	
our @EXPORT_OK=(qw(LF site_route usac_route usac_site usac_prefix usac_id usac_controller usac_host usac_middleware usac_innerware usac_outerware usac_static_content usac_cached_file usac_mime_db usac_mime_default usac_site_url usac_dirname usac_path $Path $Comp $Query $File_Path $Dir_Path $Any_Method
	), @errors,@redirects);

our @EXPORT=@EXPORT_OK;

use uSAC::HTTP::Code qw<:constants>;
use uSAC::HTTP::Method qw<:constants>;
use uSAC::HTTP::Header qw<:constants>;
use uSAC::HTTP::Constants;

use uSAC::HTTP::Rex;
use uSAC::HTTP::Cookie qw<:all>;
use uSAC::HTTP::v1_1_Reader;      #TODO: this will be dynamically linked in
use Sub::Middler;

use File::Spec::Functions qw<rel2abs abs2rel>;
use File::Basename qw<dirname>;


class uSAC::HTTP::Site;

no warnings "experimental";
field $_server      :mutator :param=undef;
field $_parent      :mutator :param=undef;
field $_prefix      :reader :param =undef;
field $_host        :reader :param =[];
field $_id          :mutator :param=undef;
field $_innerware   :mutator :param=[];
field $_outerware   :mutator :param=[];
field $_error_uris  :param={};
field $_controller  :mutator :param=undef;

field $_mime_default:mutator;
field $_mime_db     :mutator;
field $_mime_lookup :mutator;
field $_mount;
field $_cors;
field $_unsupported;
field $_built_prefix;
field $_built_label;
field $_mode      :mutator :param=undef; #server false, client true


my @supported_methods=qw<HEAD GET PUT POST OPTIONS PATCH DELETE UPDATE>;

our $ANY_METH=qr/^(?:GET|POST|HEAD|PUT|UPDATE|DELETE|PATCH|OPTIONS) /;
our $ANY_URL=qr/.*+ /;
our $ANY_VERS=qr/HTTP.*$/;
our $Any_Method	=qr/(?:GET|POST|HEAD|PUT|UPDATE|DELETE|PATCH|OPTIONS)/;

our $Method=		qr{^([^ ]+)};

#NOTE Path matching tests for a preceeding /
our $Path=		qr{(?:<=[/])([^?]*)};		#Remainder of path components  in request line
our $File_Path=		qr{(?:<=[/])([^?]++)(?<![/])};#[^/?](?:$|[?])};
our $Dir_Path=		qr{(?:<=[/])([^?]*+)(?<=[/])};

#NOTE Comp matching only matches between slashes
our $Comp=		qr{(?:[^/?]+)};		#Path component
our $Decimal=   qr{(?:\d+)};    #Decimal Integer
our $Word=      qr{(?:\w+)};    #Word

my $id=0;


BUILD{
  $_server//=$self;
  $_id//=$id++;
  $_prefix//="";

  if(defined($_host) and ref $_host ne "ARRAY"){
    $_host=[$_host];
  }
  else {
    $_host=[];
  }
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
  say caller;
  #my $self=shift;
  my $end;
  my $method_matcher=shift;
  my $path_matcher=shift;


  # Test we have a valid method matcher against supported methods
  #
  $method_matcher=$self->_method_match_check($method_matcher);
  say "METHOD MATCHER: ", $method_matcher;
  die "Method specification invalid for route" unless $method_matcher;



  # Fix up and break out middleware
  #
  \my (@inner, @outer, @names)=$self->wrap_middleware(@_);
  
  use Data::Dumper;
  say "INNER WARE: ".join ", ", @inner;
  say "OUTER WARE: ".join ", ", @outer;


  # Innerware run form parent to child to route in
  # the order of listing
  #
  unshift @inner, $self->construct_innerware;

  # Outerware is in reverse order
  unshift @outer, $self->construct_outerware;
  @outer=reverse @outer;

  unshift @inner , uSAC::HTTP::Rex->mw_dead_horse_stripper($_built_prefix);


  my $root=$self->find_root;
  # TODO: fix this for client support.
  # Server has the rex_write hook at the start of outerware
  # Client will need to hook at end of outerware?
  if($root->mode==0){
    Log::OK::TRACE and log_trace __PACKAGE__. " end is server ".join ", ", caller;
    use Error::Show;
    my @frames;
    my $i=0;
    push @frames, [caller $i++] while caller $i;;
    say Error::Show::context reverse=>1, frames=>\@frames;
    $end= \&rex_write;
  }
  else{
    #1 client
    #
    Log::OK::TRACE and log_trace __PACKAGE__. " end is client ".join ", ", caller;
    $end=sub {
      say STDERR __PACKAGE__.": END OF CLIENT INNNERWARE CHAIN";
      if($_[CB]){
        #More data to come
        say STDERR __PACKAGE__." CALLBACK, expecting more data from parser";
        #
      }
      else {
        #No there isn't
        say STDERR __PACKAGE__." NO CALLBACK, expecting no more data from parser";

        # Put the still connected session back into the pool for the table
        #Push the session into the idle queue?
        use Data::Dumper;
        say join ", ", $_[ROUTE][1]->@*;
        #$_[ROUTE][1][4][ACTIVE_COUNT]--;
        #$_[ROUTE][1][ROUTE_CTX_TABLE][ACTIVE_COUNT]--;
        #push $_[ROUTE][1][ROUTE_CTX_TABLE][IDLE_POOL]->@*, $_[REX][uSAC::HTTP::Rex::session_];
        my $timer;
        my ($entry, $session)= ($_[ROUTE][1][ROUTE_CTX_TABLE], $_[REX][uSAC::HTTP::Rex::session_]);
        $timer=AE::timer 0,0, sub {
        #$self->_request($_[ROUTE][1][ROUTE_CTX_TABLE], $_[REX][uSAC::HTTP::Rex::session_]);
          $self->_request($entry, $session);
          $timer=undef;
        }
      }
      #
      # The route used is always associated with a host table. Use this table
      # and attempt to the next item in the requst queue for the host

    };
  }





  #my $server= $self->[server_];
  my $static_headers=$_server->static_headers;

  #TODO: Need to rework this for other HTTP versions
  #my $root=$self->find_root;

  my $serialize=uSAC::HTTP::v1_1_Reader::make_serialize mode=>$root->mode, static_headers=>$static_headers;

  my $outer_head;
  if(@outer){
    my $middler=Sub::Middler->new();
    $middler->register($_) for(@outer);

    $outer_head=$middler->link($serialize); #TODO: Pass in the site or the route as a
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
    $inner_head=$middler->link($end);
  }
  else{
    $inner_head=$end;
  }





  my @hosts;

  @hosts=$self->build_hosts;	#List of hosts (as urls) 

  push @hosts, "*.*" unless @hosts;


  #$hosts{"*.*"}//= {};
  Log::OK::DEBUG and log_debug __PACKAGE__. " Hosts for route ".join ", ", @hosts;
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

    my ($matcher, $type)=$self->__add_route($host, $method_matcher, $path_matcher);
    $_server->add_host_end_point($host, $matcher, [$self, $inner_head, $outer_head,0], $type);
    last unless defined $matcher;

  }
}

method __add_route {
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
  #is this right?
  elsif($path_matcher =~ /[(\^\$]/){
    $type=undef;
    #$pm=$path_matcher;
    $matcher=qr{^$method_matcher $bp$path_matcher};
  }

  elsif($path_matcher =~ /\$$/){
    #$pm=substr $path_matcher, 0, -1;
    Log::OK::TRACE and log_trace "Exact match";
    $type="exact";
    $matcher="$method_matcher $bp$path_matcher";
  }
  else {
    $type="begin";
    #$pm=$path_matcher;
    $matcher="$method_matcher $bp$path_matcher";
  }

  ($matcher, $type);
}

# Fix middle described only as a sub
# Resolve controller-by-name middleware specs
#
method wrap_middleware {
  Log::OK::TRACE and log_trace __PACKAGE__. " wrap_middleware";
#my $self=shift;
  my @inner;
  my @outer;
  my @names;

  while(@_){
    #$end=$_;
    local $_=shift;
    # If the element is a code ref it is innerware ONLY
    if(ref eq "CODE"){
      Log::OK::TRACE and log_trace __PACKAGE__. " Plain singlar CODE ref. Wrapping as Innerware";
      # A straight code reference does not have any calls to 'next'.
      # wrap it in one
      my $target=$_; #User supplied sub
      
      my $sub=sub {  #Sub which will be called during linking
        my $next=shift;
        sub {         #wrapper sub (inner middleware)
          #&$target;   #User supplied
          #  &$next unless $_[REX][uSAC::HTTP::Rex::in_progress_];     #Call next here
          #
          &$target and &$next;
        }
      };
      push @inner, $sub;
    }

    # If its an array ref, then it might contain both inner
    # and outerware and possible a name
    elsif(ref eq "ARRAY"){
      Log::OK::TRACE and log_trace __PACKAGE__. " ARRAY ref. Unwrap as inner and outerware";
      #check at least for one code ref
      if(ref($_->[0]) ne "CODE"){
        Log::OK::WARN and log_warn __PACKAGE__." Innerware tuple did not have a code ref. Bypassing";
        $_->[0]=sub { state $next=shift};  #Force short circuit
      }

      if(ref($_->[1]) ne "CODE"){
        Log::OK::WARN and log_warn __PACKAGE__." Outerware tuple did not have a code ref. Bypassing";
        $_->[1]=sub { state $next=shift};  #Force short circuit
      }


      if(!defined($_->[2])){
        $_->[2]="Middleware";
      }

      say "CODE: ".$_->[0];

      say "CODE: ".$_->[1];

      push @inner, $_->[0];
      push @outer, $_->[1];
      push @names, $_->[2];

    }
    elsif(!defined){
      die Exception::Class::Base->throw("Undefined Middleware attempted");
    }
    elsif (ref eq "" ){
      # Scalar used as a method name. Call method on controller
      # and unshift the result to be processed
      # TODO: need a iteration limit here...
      my $a;
      try {
        die Exception::Class::Base->throw("No controller set for site. Cannot call method by name")unless $_controller;
        
        my $string="require $_controller";
        eval $string;
        die Exception::Class::Base->throw("Could not require $_controller: $@") if $@;
        $@=undef;

        $string="$_controller->".$_;
        $a=eval $string;
        die Exception::Class::Base->throw("Could not run $_controller with method $_. $@") if $@;
      }
      catch($e){
        say $e;
        log_error Error::Show::context message=>$e, frames=>[$e->trace->frames];
        exit -1;
      }
      unshift @_, $a;
    }
    else {
      #Ignore anything else
      #TODO: check of PSGI middleware and wrap
    }
  }
  # Return references
  (\@inner, \@outer, \@names);

}


method parent_site :lvalue{
  $_parent;
}

sub usac_site_url {
	my $self=$uSAC::HTTP::Site;
	my $url=$self->built_prefix;
	if($_[0]//""){
		return "$url/$_[0]";
	}
	$url
}

#returns (and builds if required), the prefixs for this sub site
method built_prefix {
	my $parent_prefix;
	if($self->parent_site){
		$parent_prefix=$self->parent_site->built_prefix;
	}
	else {
		$parent_prefix="";

	}
	$_built_prefix//($self->set_built_prefix($parent_prefix.$self->prefix));#$_[0][prefix_]);
}

method set_built_prefix {
  $_built_prefix=$_[0];
#$_[0][built_prefix_]=$_[1];
}

method build_hosts {
	my $parent=$_[0];
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
	my $parent=$_[0];
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
	my $parent=$_[0];
	my @outerware;
	while($parent){
		unshift @outerware, @{$parent->outerware//[]};
		$parent=$parent->parent_site;
	}
	@outerware;
}

method built_label {
	my $parent_label;
	if($_[0]->parent_site){
		$parent_label=$_[0]->parent_site->built_label;
	}
	else {
		$parent_label="";

	}
	$_built_label//($_[0]->set_built_prefix($parent_label.$_[0]->build_label));
}

#Resolves the ext to mime table the hierarchy. Checks self first, then parent
sub resolve_mime_lookup {
	my $parent=$_[0];
	my $db;;
	while($parent) {
		$db=$parent->mime_db;
		last if $db;
		$parent=$parent->parent_site;
	}
		
	$db?($db->index)[0]:{};
}

#Resolves the default mime in the hierarchy. Checks self first, then parent
sub resolve_mime_default {
	my $parent=$_[0];
	my $default;
	while($parent) {
		$default=$parent->mime_default;
		last if $default;
		$parent=$parent->parent_site;
	}
		
	$default?$default:"applcation/octet-stream";
}


sub usac_site :prototype(&) {
	#my $server=$_->find_root;
	my $server=$uSAC::HTTP::Site->find_root;
	my $sub=pop;
  my %options=@_;
	my $self= uSAC::HTTP::Site->new(server=>$server, mode=>$server->mode);
	$self->parent=$options{parent}//$uSAC::HTTP::Site;
	$self->id=$options{id}//join ", ", caller;
	$self->set_prefix(%options,$options{prefix}//'');
	
	local  $uSAC::HTTP::Site=$self;
	$sub->($self);
	$self;
}

method find_root {
  #my $self=$_[0];
	#locates the top level server/group/site in the tree
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
#Fixes missing slashes in urls
#As it is likely that the url is a constant, @_ is shifted/unshifted
#to create new variables for the things we need to correct
sub usac_route {
	#my $self=$_;	#The site to use
	my $self=$uSAC::HTTP::Site;
	$self->add_route(@_);
}

method _method_match_check{
    my $result;
    my ($matcher)=@_;
    $result =$matcher if grep $_ =~ /$matcher/, $self->supported_methods;
    die "Invalid method matcher. Does not match any methods" unless $result;
    $matcher;

}

method add_route {
  #my $self=shift;
  die "route needs at least two parameters" unless @_>=2;
  say "\nAdding route: in site";
  say join ", ",@_;
  
  if(!defined($_[0])){
    # 
    # Sets the default for the host
    #
    shift; unshift @_, $self->any_method, undef;
		$self->_add_route(@_);
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
    $b=qr{$b} if defined $b;
    unshift @_, $a, $b;

		$self->_add_route(@_);
	}


	elsif(ref($_[0]) eq "Regexp"){
		if(@_>=3){
			#method matcher specified
			$self->_add_route(@_);
		}
		else {
      #Path matcher is a regex
			unshift @_, "GET";
			$self->_add_route(@_);
		}
	}
	elsif($_[0]=~m|^/|){
		#starting with a slash, short cut for GET and head
    Log::OK::WARN and log_warn "No method supplied.  Assuming ".$self->default_method;
		unshift @_, $self->default_method;
		$self->_add_route(@_);
	}
	else{
		# method, url and middleware specified
		$self->_add_route(@_);
	}
}

sub usac_controller {
      my $controller=pop;
      unless($controller){
        # If controller is called with no arguments then make it the same package as the caller?
        my ($controller,undef,undef)=caller;
      }
      my %options=@_;
      my $self=$options{parent}//$uSAC::HTTP::Site;
      #$self->controller(%options, $controller);
      $self->controller=$controller;
}


sub usac_id {
        my $id=pop;
        my %options=@_;
        my $self=$options{parent}//$uSAC::HTTP::Site;
        #$self->set_id(%options, $id);
        $self->id=$id;
}

sub usac_prefix {
        my $prefix=pop;
        my %options=@_;
        my $self=$options{parent}//$uSAC::HTTP::Site;
        $self->set_prefix(%options,$prefix);
}

method set_prefix {
  #my $self=shift;
  my $prefix=pop;
	my %options=@_;
  return unless $prefix;
	unless($prefix=~m|^/|){

		#Log::OK::TRACE and 
		log_info "Prefix '$prefix' needs to start with a '/'. Fixing it...";
		$prefix="/".$prefix;
	}
	#$self->[prefix_]=$_;
	$_prefix=$prefix;#$uSAC::HTTP::Site;
	$_built_prefix=undef;	#force rebuilding
	$self->built_prefix;		#build abs prefix
}


sub usac_host {
	my $host=pop;	#Content is the last item
	my %options=@_;
	my $self=$options{parent}//$uSAC::HTTP::Site;
	$self->add_host(%options,$host);
}

#Options could include CA and server key paths
method add_host {
  #my $self=shift;
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


sub usac_middleware {
  #TODO: fix so specifid like a route
	#my $self=$_;
	my $mw=pop;	#Content is the last item
	my %options=@_;
	my $self=$options{parent}//$uSAC::HTTP::Site;
	$self->add_middleware(%options, $mw);
}

method add_middleware {
  #TODO: fix so specifid like a route
  #my $self=shift;
	my $mw=pop;	#Content is the last item
	my %options=@_;
	push $_innerware->@*, $mw->[0];
	push $_outerware->@*, $mw->[1];

}


########## Error handling - server side

sub usac_catch_route {
	#Add a route matching all methods and any path	
	$uSAC::HTTP::Site->add_route(qr{(?#SITE CATCH ALL)[^\s]+} ,qr{.*},pop);
}

sub usac_error_route {
	$uSAC::HTTP::Site->add_error_route(@_);
}

method add_error_route {
  #my $self=shift;
	#Force the method to match GET
	unshift @_, "GET";
	$self->add_route(@_);
}

sub usac_error_page {
	#my $self=
	$uSAC::HTTP::Site->set_error_page(@_);
}

method set_error_page {
  #my $self=shift;
	my $bp=$self->built_prefix;

	for my($k, $v)(@_){
		$_error_uris->{$k}="$bp$v";
	}
}

method error_uris {
  $_error_uris;
}

#########

#returns a sub which always renders the same content.
#http code is always
sub usac_static_content {
	my $static=pop;	#Content is the last item
	my %options=@_;
	my $self=$options{parent}//$uSAC::HTTP::Site;

	$self->add_static_content(%options, $static);
}

method add_static_content {
  #my $self=shift;
	my $static=pop;	#Content is the last item
	my %options=@_;
	my $mime=$options{mime}//$self->resolve_mime_default;
	my $headers=$options{headers}//[];
	#my $type=[HTTP_CONTENT_TYPE, $mime];
  [
	sub {
      my $next=shift;
      sub {
        if($_[HEADER]){
          push $_[HEADER]->@*, 
          HTTP_CONTENT_TYPE, $mime,
          HTTP_CONTENT_LENGTH, length($static),
          @$headers;
        }
        $_[PAYLOAD]=$static if $_[CODE];
        #&rex_write;
        &$next;
      }
	}
  , sub {
      my $next=shift;
  
    }
  ]

}

sub usac_cached_file {
	my $path=pop;
	my %options=@_;
	my $self=$options{parent}//$uSAC::HTTP::Site;

	$self->add_cached_file(%options, $path);
}

method add_cached_file {
#my $self=shift;
	my $path=pop;
	my %options=@_;
	#resolve the file relative path or 
	#$path=dirname((caller)[1])."/".$path if $path =~ m|^[^/]|;

	my $mime=$options{mime};
	my $type;
	if($mime){
		#manually specified mime type
		$type=$mime;
	}
	else{
		my $ext=substr $path, rindex($path, ".")+1;
		Log::OK::TRACE and log_trace "Extension: $ext";
		$type=$self->resolve_mime_lookup->{$ext}//$self->resolve_mime_default;
		Log::OK::TRACE and log_trace "type: $type";
		$options{mime}=$type;
	}

	if( stat $path and -r _ and !-d _){
		my $entry;
		open my $fh, "<", $path;
		local $/;
		$entry->[0]=<$fh>;
		$entry->[1]=[HTTP_CONTENT_TYPE, $type];
		$entry->[2]=(stat _)[7];
		$entry->[3]=(stat _)[9];
		close $fh;

		#Create a static content endpoint
		usac_static_content(%options, $entry->[0]);
	}
	else {
		log_error "Could not add hot path: $path";
	}
}

#set the default mime for this level
sub usac_mime_default{
	my $default=pop;
	my %options=@_;
	my $self=$options{parent}//$uSAC::HTTP::Site;
	$self->set_mime_default(%options, $self);
}

method set_mime_default {
  #my $self=shift;
	my $default=pop;
	my %options=@_;
	$self->mime_default=$default//"application/octet-stream";

}

#Set the mime db for this level
#TODO should argument be a path to a file?
sub usac_mime_db{
	my $db=pop;
	my %options=@_;
	my $self=$options{parent}//$uSAC::HTTP::Site;
	$self->set_mime_db(%options, $db);
}

method set_mime_db {
#my $self=shift;
	my $db=pop;
	my %options=@_;
	$self->mime_db=$db;
	($self->mime_lookup)=$self->mime_db->index;

}

#HELPERS..
#
#

#returns the dir of the caller.
#Path is abs path, so files loaded via a symlink will refer to 
#the origina path
sub usac_dirname :prototype(){
	my %options=@_;	
	#Use Cwd::abs_path to normalise path
	#Use File::Spec::Functions::abs2rel to make relative
	
	my $path=abs2rel abs_path((caller)[1]);
	return dirname $path;
}

#Make a path suitable for loading  files via do scripts
#Makes paths relative to specified root dir
#Prepends a "./" for relative files.
sub usac_path {
	my $in_path=pop;
	my %options=@_;
	return $in_path if ($in_path=~m|^/|); #If path is abs, let it be
	
	my $path;
	if ($options{root}){
		$path=$options{root};
		$path.="/".$in_path if $in_path and $path;
	}
	else {
		$path=$in_path;
	}

	#$path=abs2rel($path, $options{root});
	#
	if( $path =~ m|^/|){
		#abs path. Do nothing more
	}
	elsif($path!~m|^\.+/|){
		#relative path, but no leading dot slashe
		$path="./".$path;
	}
	else {
		#assume ok
	}
	$path;
}


#Immediate redirects

sub usac_redirect_see_other {
	my $url =pop;
	sub {
		$_[PAYLOAD]=$url;
		&rex_redirect_see_other;#@_, $url;
	}

}

sub usac_redirect_found{
	my $url =pop;
	sub {
		$_[PAYLOAD]=$url;
		&rex_redirect_found;#@_, $url;
	}
}

sub usac_redirect_temporary {
	my $url =pop;
	sub {
		$_[PAYLOAD]=$url;
		&rex_redirect_temporary;#@_, $url;
	}
}

sub usac_redirect_not_modified {
	my $url =pop;
	sub {
		$_[PAYLOAD]=$url;
		&rex_redirect_not_modified;#@_, $url;
	}
}

sub usac_redirect_internal {
	my $url =pop;
	sub {
		$_[PAYLOAD]=$url;
		&rex_redirect_internal;# @_, $url;
		#rex_write (@_,HTTP_NOT_MODIFIED, [HTTP_LOCATION, $url],"");
	}

}

sub usac_error_not_found {
	\&rex_error_not_found;
}


1;
