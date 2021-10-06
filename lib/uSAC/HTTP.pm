package uSAC::HTTP;
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
	
our @EXPORT_OK=(qw(LF site_route usac_route usac_site usac_prefix usac_id usac_host usac_innerware usac_site_url usac_static_content usac_cached_file $Path $Any_Method), @redirects);

our @EXPORT=@EXPORT_OK;

use AnyEvent;

#use uSAC::HTTP::Server;

use uSAC::HTTP::Code qw<:constants>;
use uSAC::HTTP::Method qw<:constants>;
use uSAC::HTTP::Header qw<:constants>;

use uSAC::HTTP::Rex;
use uSAC::HTTP::Cookie qw<:all>;
use uSAC::HTTP::v1_1_Reader;
use uSAC::HTTP::Static;
use uSAC::HTTP::Server::WS;
#use Hustle::Table;
use uSAC::HTTP::Middler;
use uSAC::HTTP::Middleware ":all";#qw<log_simple authenticate_simple>;

use Data::Dumper;
use File::Spec::Functions qw<rel2abs>;
use File::Basename qw<dirname>;
#Class attribute keys
use enum ("server_=0",qw(prefix_ id_ mount_ cors_ middleware_ host_ parent_ unsupported_ built_prefix_));

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
	unshift @inner, $self->_strip_prefix if $self->[prefix_];	#make strip prefix first of middleware
	#push @inner, $self->[middleware_]->@* if $self->[middleware_];
	push @inner, $self->construct_middleware;

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
		#my @hosts=$self->[host_]->@*;
		my @hosts=$self->build_hosts;
		push @hosts, qr{[^ ]+} unless @hosts;
		my $host_match="(?:".((join "|", @hosts)=~s|\.|\\.|gr).")";
		my $bp=$self->built_prefix;
		$matcher=qr{^$host_match $method_matcher $bp$path_matcher};
		#$matcher=qr{^$self->[host_] $method_matcher $bp$path_matcher};
	}
	else {
		$matcher=qr{^$method_matcher $bp$path_matcher};

                #######################################################################################
                # if($self->[host_]->@*){                                                             #
                #         warn "Server not configured for virtual hosts. Ignoring host specificatoin" #
                # }                                                                                   #
                #######################################################################################
	}
	say "  matching: $matcher";	
	my $outer;
	if(@inner){
		my $middler=uSAC::HTTP::Middler->new();
		for(@inner){
			$middler->register($_);
		}
		($end,$outer)=$middler->link($end);
	}
	$outer//=sub {@_};
	$self->[server_]->add_end_point($matcher, $end, [$self,$outer]);
	my $tmp=join "|", @non_matching;
	my $mre=qr{$tmp};
	my $unsupported;
	if($self->[server_]->enable_hosts){
		my @hosts=$self->build_hosts;
		#my @hosts=$self->[host_]->@*;
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
		my $outer_next=shift;
		(
			sub {
				$_[1]->[uSAC::HTTP::Rex::uri_stripped_]= substr($_[1]->[uSAC::HTTP::Rex::uri_], $len);
				return &$inner_next;
			},

			$outer_next
		)
	}

}
##################################################################################################
# sub _cors {                                                                                    #
#         my $self=shift;                                                                        #
#         my $prefix=$self->[prefix_];                                                           #
#         sub {                                                                                  #
#                 my $next=shift;                                                                #
#                 say "making strip prefix";                                                     #
#                 sub {                                                                          #
#                         #Do a cors test on request                                             #
#                         {                                                                      #
#                                 ($_[1][uSAC::HTTP::Rex::headers_]{orign}//"*"=~$self->[cors_]) #
#                                                                                                #
#                         }                                                                      #
#                                                                                                #
#                         return &$next;                                                         #
#                 }                                                                              #
#         }                                                                                      #
#                                                                                                #
# }                                                                                              #
#                                                                                                #
##################################################################################################

sub server {
	return $_[0][server_];
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
	while($parent->parent_site){
		push @hosts, $parent->[host_]->@*;	
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
our $Path=		qr{(/[^? ]*)};		#Remainder of path components  in request line
our $Comp=		qr{/([^/ ]+)};		#Path component
our $Query=		qr{(?:[?]([^# ]+)?)?};
our $Fragment=		qr{(?:[#]([^ ]+)?)?};

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

=over 

=item C<usac_site>

Creates a new site and sets the server to the C<$_> dynamic variable
After the server is set. the C<$_> in localised and set to the new site

=back

=cut

sub usac_site :prototype(&) {
	my $server=$_->find_root;
	my $sub=shift;
	my $self= uSAC::HTTP->new(server=>$server);
	$self->[parent_]=$_;
	
	#$self->[host_]=$self->[parent_]->host; #inherit parent host
	local  $_=$self;
	$sub->();
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

sub usac_route {
	my $self=$_;	#The site to use
	#first element is tested for short cut get use
	given($_[0]){
		when(ref eq "ARRAY"){
			#Methods specified as an array ref
			my $a=shift;
			unshift @_, "(?:".join("|", @$a).")";
			$self->add_route(@_);
		}
		when(m|^/|){
			#starting with a slash, short cut for GET and head
			unshift @_, "GET";
			$self->add_route(@_);
		}
		default{
			#normal	
			$self->add_route(@_);
		}
	}
}

sub usac_id {
	my $self=$_;
	$self->[id_]=shift;
}

sub usac_prefix {
	my $self=$_;
        given(my $prefix=shift){
                unless(m|^/|){
                        warn "Prefix '$_' needs to start with a '/'. Fixing";
                        $_="/".$_;
                }
		$self->[prefix_]=$_;
		$self->[built_prefix_]=undef;	#force rebuilding
		$self->built_prefix;		#build abs prefix
        }
}

sub usac_host {
	my $self=$_;
	push $self->[host_]->@*, @_;
}

sub usac_innerware {
	my $self=$_;
	say "ADDING MIDDLE WARE";	
	if(ref($_[0])eq"ARRAY"){
		$self->[middleware_]=shift;
	}
	else{
		$self->[middleware_]=[@_];
	}
}

sub usac_error_page {
		
}
#returns a sub which always renders the same content.
#http code is always
sub usac_static_content {
	my $static=pop;	#Content is the last item
	my $ext=$_[0]//"txt";
	sub {
		my $headers=
		[[HTTP_CONTENT_TYPE, ($uSAC::HTTP::Server::MIME{$ext}//$uSAC::HTTP::Server::DEFAULT_MIME)]];
		rex_reply_simple @_, HTTP_OK, $headers, $static; return
	}
}

#Arguments the same as usac_route, however, last item is a file relative path
sub usac_cached_file {
	my $self=$_;
	my $path=pop;
	#resolve the file relative path or 
	$path=dirname((caller)[1])."/".$path if $path =~ m|^[^/]|;
	if( stat $path and -r _ and !-d _){
		my $entry;
		open my $fh, "<", $path;
		local $/;
		$entry->[0]=<$fh>;
		my $ext=substr $path, rindex($path, ".")+1;
		$entry->[1]=[ HTTP_CONTENT_TYPE, ($uSAC::HTTP::Server::MIME{$ext}//$uSAC::HTTP::Server::DEFAULT_MIME)];
		$entry->[2]=(stat _)[7];
		$entry->[3]=(stat _)[9];
		close $fh;

		#Create a static content endpoint
		usac_static_content($ext=>$entry->[0]);
	}
	else {
		say "Could not add hot path: $path";
	}
}

######################################################################
# sub usac_favicon {                                                 #
#         my $path=shift;                                            #
#                                                                    #
#         $path=dirname((caller)[1])."/".$path if $path =~ m|^[^/]|; #
#         $path=rel2abs($path);                                      #
#         say $path;                                                 #
#         usac_route "/favicon.png" => usac_cached_file $path;       #
#                                                                    #
# }                                                                  #
######################################################################

#*usac_static_from = *static_file_from;


1;
