package uSAC::HTTP;
use warnings;
use strict;

use version; our $VERSION=version->declare("v0.0.1");
use feature ":all";
no warnings "experimental";

use Exporter "import";

our @EXPORT_OK=qw(LF site_route define_route define_site define_prefix define_id define_host define_middleware $Path $Any_Method);
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

#Class attribute keys
use enum ("server_=0",qw(prefix_ id_ mount_ cors_ middleware_ host_ parent_ unsupported_ built_prefix_));

use constant KEY_OFFSET=>	0;
use constant KEY_COUNT=>	built_prefix_-server_+1;

use constant LF=>"\015\012";



sub new {
	my $self=[];
	my $package=shift//__PACKAGE__;
	my %options=@_;
	$self->[server_]=	$options{server};
	$self->[id_]=		$options{id};
	$self->[prefix_]=	$options{prefix}//"";
	$self->[host_]=		$options{host}//"";
	$self->[cors_]=		$options{cors}//"";
	$self->[middleware_]=	$options{middleware}//[];
	$self->[unsupported_]=[];

	#die "No server provided" unless $self->[server_];
	#die "No id provided" unless $self->[id_];

	bless $self, __PACKAGE__;
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
	my $self=shift;
	my $method_matcher=shift;
	my $path_matcher=shift;
	my $end=pop @_;
	my @inner=@_;
	unshift @inner, $self->_strip_prefix if $self->[prefix_];	#make strip prefix first of middleware
	push @inner, $self->[middleware_]->@* if $self->[middleware_];

	#die "No Matcher provided " unless $matcher//0;
	die "No end point provided" unless $end and ref $end eq "CODE";
	state @methods=qw<HEAD GET PUT POST OPTIONS PATCH DELETE UPDATE>;

	my @non_matching=(qr{[^ ]+});#grep {!/$method_matcher/} @methods;
	#my @non_matching=grep {!/$method_matcher/} @methods;
	my @matching=grep {/$method_matcher/ } @methods;
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
		my $bp=$self->built_prefix;
		$matcher=qr{^$self->[host_] $method_matcher $bp$path_matcher};
	}
	else {
		$matcher=qr{^$method_matcher $bp$path_matcher};

		if($self->[host_]){
			warn "Server not configured for virtual hosts. Ignoring host specificatoin"
		}
	}
	say "  matching: $matcher";	
	$self->[server_]->add_end_point($matcher,$end);
	my $tmp=join "|", @non_matching;
	my $mre=qr{$tmp};
	my $unsupported;
	if($self->[server_]->enable_hosts){
		$unsupported=qr{^$self->[host_] $mre $bp$path_matcher};
		
	}
	else {
		$unsupported=qr{^$mre $bp$path_matcher};
	}
	#say "Unmatching: $unsupported";	
	#$self->[server_]->add_end_point($unsupported,$sub, $self);
	push $self->[unsupported_]->@*, [$unsupported, $sub,$self];

	my ($entry,$stack);
	if(@inner){
		my $middler=uSAC::HTTP::Middler->new();
		for(@inner){
			$middler->register($_);
		}
		($end,$stack)=$middler->link($end);
	}
}

#middleware to strip prefix
sub _strip_prefix {
	my $self=shift;
	my $prefix=$self->[built_prefix_];
	my $len=length $prefix;
	sub {
		my $next=shift;
		sub {
                        #{
                                #NOTE: block used to make temp dynamic scope to protect capture groups
                                #being destroyed when running another match
                                #The space  is to prevent the host matching if present
                                shift @_;
                                for($_[0]){     #this is actually arg 1
                                        $_->[uSAC::HTTP::Rex::uri_stripped_]= substr($_->[uSAC::HTTP::Rex::uri_],$len);
                                        unshift @_, $_->[uSAC::HTTP::Rex::host_]." ".$_->[uSAC::HTTP::Rex::method_]." ".$_->[uSAC::HTTP::Rex::uri_stripped_];
                                }
                                #$new=$_[0]=~s/ $prefix/ /nr;
                                return &$next;
                                #}
			#my $new;
                        #########################################################################################################################################
                        # {                                                                                                                                     #
                        #         #NOTE: block used to make temp dynamic scope to protect capture groups                                                        #
                        #         #being destroyed when running another match                                                                                   #
                        #         #The space  is to prevent the host matching if present                                                                        #
                        #         shift @_;                                                                                                                     #
                        #         given($_[0]){                                                                                                                 #
                        #                 $_->[uSAC::HTTP::Rex::uri_stripped_]=$_->[uSAC::HTTP::Rex::uri_]=~s/$prefix//nr;                                      #
                        #                 unshift @_, $_->[uSAC::HTTP::Rex::host_]." ".$_->[uSAC::HTTP::Rex::method_]." ".$_->[uSAC::HTTP::Rex::uri_stripped_]; #
                        #         }                                                                                                                             #
                        #         #$new=$_[0]=~s/ $prefix/ /nr;                                                                                                 #
                        #                                                                                                                                       #
                        #         #The @_ is shifted to remove the alias of "line"                                                                              #
                        #         #Otherwise the above modifies the original input which effects the                                                            #
                        #         #Hustle::Table cache                                                                                                          #
                        #         return &$next;#->($new, @_);                                                                                                  #
                        # }                                                                                                                                     #
                        #########################################################################################################################################
		}
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
sub parent_site {
	$_[0][parent_];
}
sub unsupported {
	return $_[0]->[unsupported_];
}

#returns (and builds if required), the prefixs for this sub site
sub built_prefix {
	my $parent;
	if($_[0][parent_]){
		$parent=$_[0][parent_]->built_prefix;
	}
	else {
		$parent="";

	}
	$_[0]->[built_prefix_]//($_[0]->[built_prefix_]=$parent.$_[0][prefix_]);
}

sub host {
	$_[0]->[host_];
}

#Take matcher, list of innerware and endpoint sub

our $ANY_METH=qr/^(?:GET|POST|HEAD|PUT|UPDATE|DELETE|OPTIONS) /;
our $ANY_URL=qr/.*+ /;
our $ANY_VERS=qr/HTTP.*$/;
our $Any_Method	=qr/(?:GET|POST|HEAD|PUT|UPDATE|DELETE|OPTIONS)/;

our $Method=		qr{^([^ ]+)};
our $Path=		qr{(/[^? ]*)};	#Remainder of path components  in request line
our $Comp=		qr{/([^/ ]+)};	#Path component
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

=item C<define_site>

Creates a new site and sets the server to the C<$_> dynamic variable
After the server is set. the C<$_> in localised and set to the new site

=back

=cut

sub define_site :prototype(&) {
	my $server=$_;
	unless(ref($server)=~/Server/){
		#Acutal a site
		$server=$server->server;
	}
	my $sub=shift;
	my $self= uSAC::HTTP->new(server=>$server);
	$self->[parent_]=$_;
	$self->[host_]=$self->[parent_]->host; #inherit parent host
	local  $_=$self;
	$sub->();
}

sub define_route {
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
sub define_id {
	my $self=$_;
	$self->[id_]=shift;
}

sub define_prefix {
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

sub define_host {
	my $self=$_;
	$self->[host_]=shift;
	#$self->[server_]->set_enable_hosts(1);
}

sub define_middleware{
	my $self=$_;
	
	if(ref($_[0])eq"ARRAY"){
		$self->[middleware_]=shift;
	}
	else{
		$self->[middleware_]=[@_];
	}
}

sub define_error_page {
		
}
1;
