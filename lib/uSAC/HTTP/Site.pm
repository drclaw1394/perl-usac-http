package uSAC::HTTP::Site;
use warnings;
use strict;

use version; our $VERSION=version->declare("v0.0.1");
use feature ":all";
no warnings "experimental";

use Log::ger;
use Log::OK;
use Cwd qw<abs_path>;
use File::Spec::Functions;
use Exporter "import";

my @redirects=qw<
	usac_redirect_see_other 
	usac_redirect_found
	usac_redirect_temporary
	usac_redirect_not_modified
	usac_redirect_internal
	>;

my @errors=qw<
usac_error_not_found
>;	
	
our @EXPORT_OK=(qw(LF site_route usac_route usac_site usac_prefix usac_id usac_host usac_middleware usac_innerware usac_outerware usac_static_content usac_cached_file usac_mime_db usac_mime_default usac_site_url usac_dirname usac_path $Path $Comp $Query $File_Path $Dir_Path $Any_Method), @redirects);

our @EXPORT=@EXPORT_OK;

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
use uSAC::HTTP::Middleware qw<log_simple chunked>;

use File::Spec::Functions qw<rel2abs abs2rel>;
use File::Basename qw<dirname>;

use Data::Dumper;
#Class attribute keys
use enum ("server_=0",qw(mime_default_ mime_db_ mime_lookup_ prefix_ id_ mount_ cors_ innerware_ outerware_ host_ parent_ unsupported_ built_prefix_));

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
	$self->[innerware_]=	$options{middleware}//[];
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
my @methods=qw<HEAD GET PUT POST OPTIONS PATCH DELETE UPDATE>;
sub add_route {
	local $,=" ";
	my $self=shift;
	my $end=pop @_;
	my $method_matcher=shift;
	my $path_matcher=shift;
	my @inner;
	my @outer;
	Log::OK::TRACE and log_trace "Adding route: from ".join ", ", caller;
	Log::OK::TRACE and log_trace "Path matcher: $path_matcher";

	#Add chunked always. Add at start of total middleware
	# Than means executed first for innerware 
	# and last for outerware
	unshift @_, chunked();
	for(@_){
		#If the elemtn is a code ref it is innerware
		if(ref($_)eq "CODE"){
			push @inner, $_;
		}
		#if its an array ref, then it might contain both inner
		#and outerware
		elsif(ref($_) eq "ARRAY"){
			push @inner, $_->[0];
			push @outer, $_->[1];
		}
		else {
			#Ignore anything else
		}
	}

	
	# Innerware run form parent to child to route in
	# the order of listing
	#
	unshift @inner, $self->construct_middleware;

	# Outerware is in reverse order
	unshift @outer, $self->construct_outerware;
	@outer=reverse @outer;

	unshift @inner, $self->_strip_prefix;# if $self->[prefix_];	#make strip prefix first of middleware

	die "No end point provided" unless $end and ref $end eq "CODE";

	#my @non_matching=(qr{[^ ]+});
	Log::OK::TRACE and log_trace Dumper $method_matcher;
	my @matching=grep { /$method_matcher/ } @methods;
	my @non_matching=grep { !/$method_matcher/ } @methods;
	my $sub;
	local $"=",";
	Log::OK::TRACE and log_trace "Methods array : @matching";
	if(@non_matching){
		my $headers=[HTTP_ALLOW, join ", ",@matching];
		$sub = sub { 
			#TODO: how to add middleware ie logging?
			rex_write @_, HTTP_METHOD_NOT_ALLOWED, $headers, "";
			return;	#cache this
		};
	}

	my $outer;

	if(@inner){
		my $middler=uSAC::HTTP::Middler->new();
		for(@inner){
			$middler->register($_);
		}
		$end=$middler->link($end);
	}
	my @index=map {$_*2} 0..99;

	state $alloc="x" x 2048;
	#my $server= $self->[server_];
	my $static_headers=$self->[server_]->static_headers;
	my $serialize=
			sub{
				no warnings qw<numeric uninitialized>;

				Log::OK::TRACE and log_trace "Main serialiser";
				Log::OK::TRACE and log_trace join  " ", caller;
				#my ($matcher, $rex, $code, $headers, $data,$callback, $arg)=@_;
				#The last item in the outerware
				# renders the headers to the output sub
				# then calls 
				#
				my $cb=$_[5]//$_[1][uSAC::HTTP::Rex::dropper_];


				if($_[3]){
					\my @h=$_[3];

					#my $reply=$alloc;#."x";
					my $reply="HTTP/1.1 $_[2] ". $uSAC::HTTP::Code::code_to_name[$_[2]]. LF;
						#last if $_ >= @h;
					$reply.= $h[$_].": $h[$_+1]".LF 
					for(@index[0..@h/2-1]);

						#last if  $_ >= $static_headers->@*;
					$reply.="$static_headers->[$_]:$static_headers->[$_+1]".LF
					for(@index[0..$static_headers->@*/2-1]);

					$reply.=HTTP_DATE.": $uSAC::HTTP::Session::Date".LF;

					Log::OK::DEBUG and log_debug "->Serialize: headers:";
					Log::OK::DEBUG and log_debug $reply;

					$_[3]=undef;	#mark headers as done
					$reply.=LF.$_[4]//"";
					$_[1][uSAC::HTTP::Rex::write_]($reply, $cb, $_[6]);
				}
				else{
					$_[1][uSAC::HTTP::Rex::write_]($_[4],$cb,$_[6]);
				}
			};
	if(@outer){
		my $middler=uSAC::HTTP::Middler->new();
		$middler->register($_) for(@outer);

		$outer=$middler->link($serialize);
	}
	else {
		$outer=$serialize;
	}

	my @hosts;
	my $matcher;
	@hosts=$self->build_hosts;
        my $bp=$self->built_prefix;                                      #

        ####################################################################
        # push @hosts, qr{[^ ]+} unless @hosts;                            #
        # my $host_match="(?:".((join "|", @hosts)=~s|\.|\\.|gr).")";      #
        # my $bp=$self->built_prefix;                                      #
        # $matcher=qr{^$host_match $method_matcher $bp$path_matcher};      #
        # log_info "  matching: $matcher";                                 #
        # $self->[server_]->add_end_point($matcher, $end, [$self,$outer]); #
        ####################################################################

	push @hosts, "*.*" unless @hosts;
	#$matcher=qr{^$method_matcher $bp$path_matcher};
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

		for my $method (@matching){
			Log::OK::TRACE and log_trace "$host=>$method";
			#test if $path_matcher is a regex
			my $type;

			if(ref($path_matcher) eq "Regexp"){
				$type=undef;
				#$pm=$path_matcher;
        			$matcher=qr{$method $bp$path_matcher};
			}
			elsif($path_matcher =~ /[(\^\$]/){
				$type=undef;
				#$pm=$path_matcher;
        			$matcher=qr{$method $bp$path_matcher};
			}
			elsif($path_matcher =~ /\$$/){
				$pm=substr $path_matcher, 0, -1;
				Log::OK::TRACE and log_trace "Exact match";
				$type="exact";
        			$matcher="$method $bp$path_matcher";
			}
			else {
				$type="begin";
				#$pm=$path_matcher;
        			$matcher="$method $bp$path_matcher";
			}

			#$matcher="$method $bp$pm";
			Log::OK::DEBUG and log_debug"Adding matched endpoints";
			Log::OK::DEBUG and log_debug"  matching: $host $matcher";                                 #
			$self->[server_]->add_host_end_point($host, $matcher, [$self, $end, $outer,0], $type);
		}
	}


	my $tmp=join "|", @non_matching;
	my $mre=qr{$tmp};
	my $unsupported=qr{^$mre $bp$path_matcher};
	#push @hosts, "*.*" unless @hosts;
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
		for my $method (@non_matching){
			$unsupported="$method $bp$path_matcher";
			push $self->[unsupported_]->@*, [$host, $unsupported, [$self,$sub, $outer,0]];
			Log::OK::TRACE and log_trace "  non matching: $host $unsupported";                                 #
		}
	}
}

#middleware to strip prefix
sub _strip_prefix {
	my $self=shift;
	my $prefix=$self->[built_prefix_];
	my $len=length($prefix)//0;
	sub {
		my $inner_next=shift;
		sub {
			#package uSAC::HTTP::Rex {
				$_[1][uSAC::HTTP::Rex::uri_stripped_]= substr($_[1]->[uSAC::HTTP::Rex::uri_], $len); #strip the url
				#$_[1][capture_]=[@{^CAPTURE}];	#save the capture 

				&$inner_next; #call the next
				#Check the inprogress flag
				#TODO: The session can go out of scope here. Need a more
				#consistent approach to testing if a reply is in progress
			
				!$_[1][uSAC::HTTP::Rex::in_progress_] and Log::OK::ERROR and log_error("NO ENDPOINT REPLIED for". $_[1]->[uSAC::HTTP::Rex::uri_]);

		},

	}
}

#outerware to catch no reply
sub _catch_no_reply {
	my $self=shift;
	sub {
		my $outer_next=shift; #this should  not exist...

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


sub parent_site :lvalue{
	$_[0][parent_];
}
sub unsupported {
	return $_[0]->[unsupported_];
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
		Log::OK::TRACE and log_trace "Middleware from $parent";
		Log::OK::TRACE and log_trace "Parent_site ". ($parent->parent_site//"");
		unshift @middleware, @{$parent->innerware//[]};
		$parent=$parent->parent_site;
	}
	@middleware;
}

sub construct_outerware {
	my $parent=$_[0];
	my @outerware;
	while($parent){
		unshift @outerware, @{$parent->outerware//[]};
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





#Take matcher, list of innerware and endpoint sub

our $ANY_METH=qr/^(?:GET|POST|HEAD|PUT|UPDATE|DELETE|PATCH|OPTIONS) /;
our $ANY_URL=qr/.*+ /;
our $ANY_VERS=qr/HTTP.*$/;
our $Any_Method	=qr/(?:GET|POST|HEAD|PUT|UPDATE|DELETE|PATCH|OPTIONS)/;

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

sub innerware {
	$_[0]->[innerware_];
}
sub outerware{
	$_[0]->[outerware_];
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
		#not starting with a forward slash but with a method
		my $url=shift @_;

		#only add a slash if the strin is not empty
		$url="/".$url if $url ne "";

		unshift @_, $url;

		unshift @_, "GET";
		$self->add_route(@_);

	}
	elsif(
		$_[0]=~m|^$Any_Method| and
		$_[1]=~m|^[^/]| and
		ref($_[1]) ne "Regexp"
	){
		#Method specified but route missing a leading slash
		my $method=shift;
		my $url=shift;

		$url="/".$url if $url ne "";
		unshift @_, $method, $url;

		$self->add_route(@_);
	}
	else{
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
        my $prefix=pop;
	unless($prefix=~m|^/|){

		#Log::OK::TRACE and 
		log_info "Prefix '$prefix' needs to start with a '/'. Fixing it...";
		$prefix="/".$prefix;
	}
	#$self->[prefix_]=$_;
	$self->[prefix_]=$prefix;#$uSAC::HTTP::Site;
	$self->[built_prefix_]=undef;	#force rebuilding
	$self->built_prefix;		#build abs prefix
}


sub usac_host {
	my $host=pop;	#Content is the last item
	my %options=@_;
	my $self=$options{parent}//$uSAC::HTTP::Site;
        ######################################################
        # my @uri;                                           #
        # if(ref($host) eq "ARRAY"){                         #
        #         @uri= map {URI->new("http://$_")} @$host;  #
        # }                                                  #
        # else{                                              #
        #         @uri= map {URI->new("http://$_")} ($host); #
        # }                                                  #
        # for(@uri){                                         #
        #         die "Error parsing hosts: $_ " unless ref; #
        # }                                                  #
        # push $self->host->@*, @uri;                        #
        ######################################################
	$self->add_host(%options,$host);
}

sub add_host {
	my $self=shift;
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
	push $self->host->@*, @uri;

}


sub usac_middleware {
	#my $self=$_;
	my $mw=pop;	#Content is the last item
	my %options=@_;
	my $self=$options{parent}//$uSAC::HTTP::Site;
	$self->add_middleware(%options, $mw);
}
sub add_middleware {
	my $self=shift;
	my $mw=pop;	#Content is the last item
	my %options=@_;
	push $self->innerware->@*, $mw->[0];
	push $self->outerware->@*, $mw->[1];

}
sub usac_innerware{
	#my $self=$_;
	my $mw=pop;	#Content is the last item
	my %options=@_;
	my $self=$options{parent}//$uSAC::HTTP::Site;
	if(ref($mw)eq"ARRAY"){
		push $self->innerware->@*, @$mw;
	}
	else{
		push $self->innerware->@*, $mw;
	}
}
sub usac_outerware {
	#my $self=$_;
	my $mw=pop;	#Content is the last item
	my %options=@_;
	my $self=$options{parent}//$uSAC::HTTP::Site;
	if(ref($mw)eq"ARRAY"){
		push $self->outerware->@*, @$mw;
	}
	else{
		push $self->outerware->@*, $mw;
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
	my $headers=$options{headers}//[];
	#my $type=[HTTP_CONTENT_TYPE, $mime];
	sub {
		rex_write @_, HTTP_OK, [
			HTTP_CONTENT_TYPE, $mime,
			HTTP_CONTENT_LENGTH, length($static),
			@$headers
		],
		$static; 
		#return
	}
}

sub usac_cached_file {
	#my $self=$_;
	my $path=pop;
	my %options=@_;
	my $self=$options{parent}//$uSAC::HTTP::Site;
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

#returns the dir of the caller.
#Path is abs path, so files loaded via a symlink will refer to 
#the origina path
sub usac_dirname{
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
		rex_write (@_, HTTP_SEE_OTHER, [HTTP_LOCATION, $url],"");
	}

}
sub usac_redirect_found{
	my $url =pop;
	sub {
		rex_write (@_, HTTP_FOUND, [HTTP_LOCATION, $url],"");
	}
}
sub usac_redirect_temporary {
	my $url =pop;
	sub {
		rex_write (@_, HTTP_TEMPORARY_REDIRECT, [HTTP_LOCATION, $url],"");
	}
}

sub usac_redirect_not_modified {
	my $url =pop;
	sub {
		rex_write (@_,HTTP_NOT_MODIFIED, [HTTP_LOCATION, $url],"");
	}
}

sub usac_redirect_internal {
	my $url =pop;
	sub {
		rex_redirect_internal @_, $url;
		#rex_write (@_,HTTP_NOT_MODIFIED, [HTTP_LOCATION, $url],"");
	}

}

sub usac_error_not_found {
	sub {
		&rex_error_not_found;
	};
}


#Error Pages

1;
