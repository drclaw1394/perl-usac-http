package uSAC::HTTP::Site;
use warnings;
use strict;

use version; our $VERSION=version->declare("v0.0.1");
use feature ":all";
no warnings "experimental";

use Exporter "import";

my @redirects=qw<
	usac_redirect_see_other 
	usac_redirect_found
	usac_redirect_temporary
	usac_redirect_not_modified
	>;
	
our @EXPORT_OK=(qw(LF site_route usac_route usac_site usac_prefix usac_id usac_host usac_middleware usac_innerware usac_outerware usac_site_url usac_static_content usac_cached_file usac_mime_db usac_mime_default $Path $Comp $Query $File_Path $Dir_Path $Any_Method), @redirects);

our @EXPORT=@EXPORT_OK;

#use AnyEvent;

#use uSAC::HTTP::Server;

use uSAC::HTTP::Code qw<:constants>;
use uSAC::HTTP::Method qw<:constants>;
use uSAC::HTTP::Header qw<:constants>;

use uSAC::HTTP::Rex;
use uSAC::HTTP::Cookie qw<:all>;
use uSAC::HTTP::v1_1_Reader;
use uSAC::HTTP::Static;
#use uSAC::HTTP::Server::WS;
#use Hustle::Table;
#
use uSAC::HTTP::Middler;
use uSAC::HTTP::Middleware ":all";#qw<log_simple authenticate_simple>;

use File::Spec::Functions qw<rel2abs>;
use File::Basename qw<dirname>;

use Data::Dumper;
#Class attribute keys
use enum ("server_=0",qw(mime_default_ mime_db_ mime_lookup_ prefix_ id_ mount_ cors_ middleware_ outerware_ host_ parent_ unsupported_ built_prefix_));

use constant KEY_OFFSET=>	0;
use constant KEY_COUNT=>	built_prefix_-server_+1;

use constant LF=>"\015\012";



sub new {
	my $self=[];
	my $package=shift//__PACKAGE__;
	my %options=@_;
	$self->[server_]=	$options{server}//$self;
	$self->[id_]=		$options{id};
	$self->[prefix_]=	$options{prefix}//"";
	$self->[host_]=		$options{host}?[$options{host}]:[];
	$self->[cors_]=		$options{cors}//"";
	$self->[middleware_]=	$options{middleware}//[];
	$self->[outerware_]=	$options{outerware}//[];
	$self->[unsupported_]=[];

	#die "No server provided" unless $self->[server_];
	#die "No id provided" unless $self->[id_];

	bless $self, $package;
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
sub add_route {
	local $,=" ";
	my $self=shift;
	my $end=pop @_;
	my $method_matcher=shift;
	my $path_matcher=shift;
	my @inner=@_;
	my @outer;
	unshift @inner, $self->_strip_prefix if $self->[prefix_];	#make strip prefix first of middleware
	push @inner, $self->construct_middleware;
	push @outer, $self->construct_outerware;

	#die "No Matcher provided " unless $matcher//0;
	die "No end point provided" unless $end and ref $end eq "CODE";
	state @methods=qw<HEAD GET PUT POST OPTIONS PATCH DELETE UPDATE>;

	my @non_matching=(qr{[^ ]+});#grep {!/$method_matcher/} @methods;
	#my @non_matching=grep {!/$method_matcher/} @methods;
	my @matching=grep { /$method_matcher/ } @methods;
	my $sub;

	if(@non_matching){
		my $headers=[[HTTP_ALLOW, join ", ",@matching]];
		$sub = sub { 
			#TODO: how to add middleware ie logging?
			rex_reply_simple @_, HTTP_METHOD_NOT_ALLOWED, $headers, "";
			return;	#cache this
		};
	}

	my $matcher;
	#my $unsupported;
	my $bp=$self->built_prefix;
	if($self->[server_]->enable_hosts){
		my @hosts=$self->build_hosts;
		push @hosts, qr{[^ ]+} unless @hosts;
		my $host_match="(?:".((join "|", @hosts)=~s|\.|\\.|gr).")";
		my $bp=$self->built_prefix;
		$matcher=qr{^$host_match $method_matcher $bp$path_matcher};
	}
	else {
		$matcher=qr{^$method_matcher $bp$path_matcher};
	}
	say "  matching: $matcher";	
	my $outer;
	if(@inner){
		my $middler=uSAC::HTTP::Middler->new();
		for(@inner){
			$middler->register($_);
		}
		$end=$middler->link($end);
	}
	if(@outer){
		my $middler=uSAC::HTTP::Middler->new();
		for(@outer){
			$middler->register($_);
		}
		$outer=$middler->link(sub{});
	}

	$self->[server_]->add_end_point($matcher, $end, [$self,$outer]);
	# first argument is a 'route' object
	# 		0 site
	# 		1 outerware to execute
	my $tmp=join "|", @non_matching;
	my $mre=qr{$tmp};
	my $unsupported;
	if($self->[server_]->enable_hosts){
		my @hosts=$self->build_hosts;
		push @hosts, qr{[^ ]+} unless @hosts;
		my $host_match="(?:".((join "|", @hosts)=~s|\.|\\.|gr).")";
		$unsupported=qr{^$host_match $mre $bp$path_matcher};
		
	}
	else {
		$unsupported=qr{^$mre $bp$path_matcher};
	}
	#say "Unmatching: $unsupported";	
	#$self->[server_]->add_end_point($unsupported,$sub, $self);
	push $self->[unsupported_]->@*, [$unsupported, $sub,[$self,$outer]];
}

#middleware to strip prefix
sub _strip_prefix {
	my $self=shift;
	my $prefix=$self->[built_prefix_];
	my $len=length $prefix;
	sub {
		my $inner_next=shift;
		sub {
			$_[1]->[uSAC::HTTP::Rex::uri_stripped_]= substr($_[1]->[uSAC::HTTP::Rex::uri_], $len);
			return &$inner_next;
		},

	}

}

sub server: lvalue {
	return $_[0][server_];
}

sub id: lvalue {
	return $_[0][id_];
}

sub add_end_point {

}


sub parent_site {
	$_[0][parent_];
}
sub unsupported {
	return $_[0]->[unsupported_];
}

#returns (and builds if required), the prefixs for this sub site
sub built_prefix {
	my $parent_prefix;
	if($_[0]->parent_site){
		$parent_prefix=$_[0]->parent_site->built_prefix;
	}
	else {
		$parent_prefix="";

	}
	$_[0][built_prefix_]//($_[0]->set_built_prefix($parent_prefix.$_[0]->prefix));#$_[0][prefix_]);
}

sub set_built_prefix {
	$_[0][built_prefix_]=$_[1];
}

sub build_hosts {
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
sub construct_middleware {
	my $parent=$_[0];
	my @middleware;
	while($parent){
		unshift @middleware, @{$parent->[middleware_]//[]};
		$parent=$parent->parent_site;
	}
	@middleware;
}

sub construct_outerware {
	my $parent=$_[0];
	my @outerware;
	while($parent){
		unshift @outerware, @{$parent->[outerware_]//[]};
		$parent=$parent->parent_site;
	}
	@outerware;
}

sub prefix {
	$_[0]->[prefix_];
}

sub host {
	$_[0]->[host_];
}

#makes a url to with in the site
#match entry
#rex
#partial url
sub usac_site_url {
	#match_entry->context->built_prefix
	$_[0][4][built_prefix_].pop;		
}


#redirect to within site
#match entry
#rex
#partial url
#code
sub usac_redirect_see_other{
	my $url=usac_site_url @_;
	splice @_, 2;
	rex_reply_simple @_, HTTP_SEE_OTHER,[[HTTP_LOCATION, $url]],"";
}

sub usac_redirect_found {
	my $url=usac_site_url @_;
	splice @_, 2;
	rex_reply_simple @_, HTTP_FOUND,[[HTTP_LOCATION, $url]],"";
	
}

sub usac_redirect_temporary {
	my $url=usac_site_url @_;
	splice @_, 2;
	rex_reply_simple @_, HTTP_TEMPORARY_REDIRECT,[[HTTP_LOCATION, $url]],"";
	
}
sub usac_redirect_not_modified {
	my $url=usac_site_url @_;
	splice @_, 2;
	rex_reply_simple @_, HTTP_NOT_MODIFIED,[[HTTP_LOCATION, $url]],"";
	
}


#Take matcher, list of innerware and endpoint sub

our $ANY_METH=qr/^(?:GET|POST|HEAD|PUT|UPDATE|DELETE|OPTIONS) /;
our $ANY_URL=qr/.*+ /;
our $ANY_VERS=qr/HTTP.*$/;
our $Any_Method	=qr/(?:GET|POST|HEAD|PUT|UPDATE|DELETE|OPTIONS)/;

our $Method=		qr{^([^ ]+)};

#NOTE Path matching tests for a preceeding /
our $Path=		qr{(?<=[/])([^?]*)};		#Remainder of path components  in request line
our $File_Path=		qr{(?<=[/])([^?]++)(?<![/])};#[^/?](?:$|[?])};
our $Dir_Path=		qr{(?<=[/])([^?]*+)(?<=[/])};

#NOTE Comp matching only matches between slashes
our $Comp=		qr{([^/?]+)};		#Path component

#our $Query=		qr{(?:([^#]+))?};
#our $Fragment=		qr{(?:[#]([^ ]+)?)?};

sub begins_with {
	my $test=$_[0];
	sub{0 <= index $_[0], $test},
}

sub matches_with {
	return qr{$_[0]}o;
}

sub ends_with {
	my $test=reverse $_[0];
	sub {0 <= index reverse($_[0]), $test}
}

sub site_route {
	my $self=shift;
	$self->add_route(@_);
}
#accessor
sub mime_default : lvalue {
	$_[0]->[mime_default_];
}

#accessor 
sub mime_db: lvalue {
	$_[0]->[mime_db_];
}
sub mime_lookup: lvalue {
	$_[0]->[mime_lookup_];
}





#Resolves the ext to mime table the hierarchy. Checks self first, then parent
sub resolve_mime_lookup {
	my $parent=$_[0];
	my $db;;
	while($parent) {
		$db=$parent->mime_db;
		#say "looking up mime db in : ",$parent;
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

=over 

=item C<usac_site>

Creates a new site and sets the server to the C<$_> dynamic variable
After the server is set. the C<$_> in localised and set to the new site

=back

=cut

sub usac_site :prototype(&) {
	#my $server=$_->find_root;
	my $server=$uSAC::HTTP::Site->find_root;
	my $sub=shift;
	my $self= uSAC::HTTP::Site->new(server=>$server);
	$self->[parent_]=$uSAC::HTTP::Site;
	#$self->[parent_]=$_;
	
	local  $uSAC::HTTP::Site=$self;
	#local  $_=$self;
	$sub->();
	$self;
}

sub find_root {
	my $self=$_[0];
	#locates the top level server/group/site in the tree
	my $parent=$self;

	while($parent->parent_site){
		$parent=$parent->parent_site;
	}
	$parent;
}

#Fixes missing slashes in urls
#As it is likely that the url is a constant, @_ is shifted/unshifted
#to create new variables for the things we need to correct
sub usac_route {
	#my $self=$_;	#The site to use
	my $self=$uSAC::HTTP::Site;
	#first element is tested for short cut get use
	if(ref($_[0]) eq "ARRAY"){
		#Methods specified as an array ref
		my $a=shift;
		unshift @_, "(?:".join("|", @$a).")";
		$self->add_route(@_);
	}
	elsif(ref($_[0]) eq "Regexp"){
		unshift @_, "GET";
		$self->add_route(@_);
	}
	elsif($_[0]=~m|^/|){
		#starting with a slash, short cut for GET and head
		unshift @_, "GET";
		$self->add_route(@_);
	}
	elsif(!($_[0]=~m|^[/]|) and !($_[0]=~m|^$Any_Method|)){
		#say "FIXING PATH MATCHER";
		#not starting with a forward slash but with a method
		my $url=shift @_;
		unshift @_, "/".$url;
		unshift @_, "GET";
		$self->add_route(@_);

	}
	elsif(
		$_[0]=~m|^$Any_Method| and
		$_[1]=~m|^[^/]| and
		ref($_[1]) ne "Regexp"
	){
		#Method specified but route missing a leading slash
		#say "Fixing leading slash for: $_[1]";
		my $method=shift;
		my $url=shift;
		$url="/".$url;
		unshift @_, $method, $url;

		$self->add_route(@_);
	}
	else{
		say "DEFAULT MATCHING SETUP";
		say @_;
		#normal	
		$self->add_route(@_);
	}
}

sub usac_id {
	my $self=$uSAC::HTTP::Site;
	#my $self=$_;
	$self->[id_]=shift;
}

sub usac_prefix {
	my $self=$uSAC::HTTP::Site;
	#my $self=$_;
        my $prefix=shift;
	unless($prefix=~m|^/|){
		warn "Prefix '$prefix' needs to start with a '/'. Fixing";
		$prefix="/".$prefix;
	}
	#$self->[prefix_]=$_;
	$self->[prefix_]=$uSAC::HTTP::Site;
	$self->[built_prefix_]=undef;	#force rebuilding
	$self->built_prefix;		#build abs prefix
}


sub usac_host {
	my $host=pop;	#Content is the last item
	my %options=@_;
	my $self=$options{parent}//$uSAC::HTTP::Site;
	if(ref($host) eq "ARRAY"){

		push $self->host->@*, @$host;
	}
	else{
		push $self->host->@*, $host;
	}

}

sub usac_middleware {
	#my $self=$_;
	my $mw=pop;	#Content is the last item
	my %options=@_;
	my $self=$options{parent}//$uSAC::HTTP::Site;
	say "ADDING MIDDLE WARE";	
	push $self->[middleware_]->@*, $mw->[0];
	push $self->[outerware_]->@*, $mw->[1];
}
sub usac_innerware{
	#my $self=$_;
	my $mw=pop;	#Content is the last item
	my %options=@_;
	my $self=$options{parent}//$uSAC::HTTP::Site;
	say "ADDING INNERWARE";	
	if(ref($mw)eq"ARRAY"){
		push $self->[middleware_]->@*, @$mw;
	}
	else{
		push $self->[middleware_]->@*, $mw;
	}
}
sub usac_outerware {
	#my $self=$_;
	my $mw=pop;	#Content is the last item
	my %options=@_;
	my $self=$options{parent}//$uSAC::HTTP::Site;
	say "ADDING OUTERWARE";	
	if(ref($mw)eq"ARRAY"){
		push $self->[outerware_]->@*, @$mw;
	}
	else{
		push $self->[outerware_]->@*, $mw;
	}
}

sub usac_error_page {
		
}
#returns a sub which always renders the same content.
#http code is always
sub usac_static_content {
	my $static=pop;	#Content is the last item
	my %options=@_;
	my $self=$options{parent}//$uSAC::HTTP::Site;
	my $mime=$options{mime}//$self->resolve_mime_default;
	my $type=[HTTP_CONTENT_TYPE, $mime];
	sub {
		rex_reply_simple @_, HTTP_OK, [$type], $static; return
	}
}

sub usac_cached_file {
	#my $self=$_;
	my $path=pop;
	my %options=@_;
	my $self=$options{parent}//$uSAC::HTTP::Site;
	#resolve the file relative path or 
	$path=dirname((caller)[1])."/".$path if $path =~ m|^[^/]|;

	my $mime=$options{mime};
	my $type;
	if($mime){
		#manually specified mime type
		$type=$mime;
	}
	else{
		my $ext=substr $path, rindex($path, ".")+1;
		$type=$self->resolve_mime_lookup->{$ext}//$self->resolve_mime_default;
	}

	if( stat $path and -r _ and !-d _){
		my $entry;
		open my $fh, "<", $path;
		local $/;
		$entry->[0]=<$fh>;
		$entry->[1]=[ HTTP_CONTENT_TYPE, $type];
		$entry->[2]=(stat _)[7];
		$entry->[3]=(stat _)[9];
		close $fh;

		#Create a static content endpoint
		usac_static_content($entry->[0], mime=>$type);
	}
	else {
		say "Could not add hot path: $path";
	}
}
#set the default mime for this level
sub usac_mime_default{
	my $default=pop;
	my %options=@_;
	my $self=$options{parent}//$uSAC::HTTP::Site;
	$self->mime_default=$default//"application/octet-stream";
}

#Set the mime db for this level
#TODO should argument be a path to a file?
sub usac_mime_db{
	my $db=pop;
	my %options=@_;
	my $self=$options{parent}//$uSAC::HTTP::Site;
	$self->mime_db=$db;
	($self->mime_lookup)=$self->mime_db->index;
}
1;
