package uSAC::HTTP;
use warnings;
use strict;
use version; our $VERSION=version->declare("v0.0.1");
use feature ":all";

use Exporter "import";

our @EXPORT_OK=qw(location default_handler LF site_route $Path);
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
use enum ("server_=0",qw(prefix_ id_ mount_ cors_ middleware_ host_));

use constant KEY_OFFSET=>	0;
use constant KEY_COUNT=>	host_-server_+1;

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

	#die "No server provided" unless $self->[server_];
	die "No id provided" unless $self->[id_];

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
sub route {
	my $self=shift;
	my $method_matcher=shift;
	my $path_matcher=shift;
	my $end=pop @_;
	my @inner=@_;
	unshift @inner, $self->_strip_prefix if $self->[prefix_];
	push @inner, $self->[middleware_]->@* if $self->[middleware_];

	#die "No Matcher provided " unless $matcher//0;
	die "No end point provided" unless $end and ref $end eq "CODE";
	state @methods=qw<HEAD GET PUT POST OPTIONS PATCH DELETE UPDATE>;

	my @non_matching=grep {!/$method_matcher/} @methods;
	my @matching=grep {/$method_matcher/ } @methods;
	my $sub;

	if(@non_matching){
		my $headers=[HTTP_ALLOW, join ", ",@matching]; 
		$sub = sub { 
			#TODO: how to add middleware ie logging?
			rex_reply_simple @_, HTTP_METHOD_NOT_ALLOWED, $headers, "";
			return;	#cache this
		};
	}

	my $matcher;
	my $unsupported;
	if($self->[server_]->enable_hosts){
		$matcher=qr{^$self->[host_] $method_matcher $self->[prefix_]$path_matcher};
                my $tmp=join "|", @non_matching;
                my $mre=qr{$tmp};
                $unsupported=qr{^$mre $self->[prefix_]$path_matcher};
                $self->[server_]->add_end_point($unsupported,$sub);
	}
	else {
		$matcher=qr{^$method_matcher $self->[prefix_]$path_matcher};
                my $tmp=join "|", @non_matching;
                my $mre=qr{$tmp};
                $unsupported=qr{^$mre $self->[prefix_]$path_matcher};
                $self->[server_]->add_end_point($unsupported,$sub);

		if($self->[host_]){
			warn "Server not configured for virtual hosts. Ignoring host specificatoin"
		}
	}
	say $matcher, $end;
	my ($entry,$stack);
	if(@inner){
		my $middler=uSAC::HTTP::Middler->new();
		for(@inner){
			$middler->register($_);
		}
		($end,$stack)=$middler->link($end);
	}
	$self->[server_]->add_end_point($matcher,$end);
}
#middleware to strip prefix
sub _strip_prefix {
	my $self=shift;
	my $prefix=$self->[prefix_];
	sub {
		my $next=shift;
		say "making strip prefix";
		sub {
			my $new;
			{
				#NOTE: block used to make temp dynamic scope to protect capture groups
				#being destroyed when running another match
				#The space  is to prevent the host matching if present
				$new=$_[0]=~s/ $prefix/ /nr;
				shift @_;
			}
			#The @_ is shifted to remove the alias of "line"
			#Otherwise the above modifies the original input which effects the
			#Hustle::Table cache
			return $next->($new, @_);
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

#Take matcher, list of innerware and endpoint sub

our $ANY_METH=qr/^(?:GET|POST|HEAD|PUT|UPDATE|DELETE|OPTIONS) /;
our $ANY_URL=qr/.*+ /;
our $ANY_VERS=qr/HTTP.*$/;

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

sub welcome_to_usac {
	state $data;
	unless($data){
		local $/=undef;
		$data=<DATA>;
	}
	sub {
		rex_reply_simple @_, HTTP_OK, undef, $data;
		return; #Enable caching
	}
}
sub default_handler {
		#my ($line,$rex)=@_;
		rex_reply_simple @_, (HTTP_NOT_FOUND,undef,"Go away");
		return 1;
}
sub site_route {
	my $self=shift;
	$self->route(@_);
}
1;
__DATA__
<html>
	<body>
		Welcome to uSAC
	</body>
</html>
