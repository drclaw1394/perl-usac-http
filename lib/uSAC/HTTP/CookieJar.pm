package uSAC::HTTP::CookieJar;

# Debug
#
use feature "say";
use Data::Dumper;

my @names;
my @months = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
my $i=0;
my %months= map {$_,$i++} @months;

my $i=0;
my @days= qw(Sun Mon Tue Wed Thu Fri Sat);
my %days= map {$_,$i++} @days;
my %const_names;

my @values;

BEGIN {
	@names=qw<
		Undef
		Name
		Value
		Expires
		Max-Age
		Domain
		Path
		Secure
		HTTPOnly
		SameSite
    
    Creation-Time
    Last-Access-Time
    Persistent
    Host-Only
    Expiry-Time
    Key
    Suffix_Valid

	>;
	@values= 0 .. @names-1;

	my @same_site=qw<Lax Strict None>;

	my @pairs=
		(map { (("COOKIE_".uc $names[$_])=~tr/-'/_/r, $values[$_]) } 0..@names-1),	#elements
		(map {("SAME_SITE_".uc, $_)} @same_site)						#same site vals
	;						

	%const_names=@pairs;
}


use constant \%const_names;

use constant DEBUG=>undef;
my %reverse; @reverse{map lc, @names}=@values;
$reverse{undef}=0;			#catching

# Object system. Will use feature class asap
#
use Object::Pad;

# Fast Binary Search subroutines
#
use List::Insertion {type=>"string", duplicate=>"left", accessor=>"->[".COOKIE_KEY."]"};

# Public suffix list list
#
use Mozilla::PublicSuffix qw<public_suffix>;

# Date 
use DateTime;
use Time::Local qw<timegm_modern>;

my $tz_offset;
{
  our $LocalTZ = DateTime::TimeZone->new( name => 'local' );
  say $LocalTZ;
  my $d1=DateTime->from_epoch(epoch=>0, time_zone=>"GMT");
  my $d2=DateTime->from_epoch(epoch=>0, time_zone=>$LocalTZ);
  say $d1->offset;
  say $d2->offset;
  $tz_offset=($d2->offset-$d1->offset);
}


# Logging
#
use Log::ger; 
use Log::OK;



class uSAC::HTTP::CookieJar;

field @_cookies; # An array of cookie 'structs', sorted by the COOKIE_KEY field

field $_suffix_cache :param=undef; #Hash ref used as cache


field $_psl_path :param=undef; #Path to PSL file;


method highest_cookie_domain {
    #search for  prefix 
    my $domain=lc $_[0];
    my $highest;
    my $suffix=$_suffix_cache
      ? $_suffix_cache->{$domain}//=&public_suffix
      : &public_suffix;
    if($suffix){
      substr($domain, -(length($suffix)+1))="";

      if($domain){
        my @labels=split /\./, $domain;
        $highest=pop(@labels).".$suffix";
      }
    }
    $highest;
}



method suffix{
  $_suffix_cache
    ? $_suffix_cache->{lc $_[0]}//=&public_suffix
    : &public_suffix;
}




# Create a cookie structure. This is suitable for encode_set_cookie, or set_cookies
#
sub create_cookie {

  no warnings "experimental";
  my @c;

	$c[COOKIE_NAME]=shift;
	$c[COOKIE_VALUE]=shift;

  for my ($k, $v)(@_){
		$c[$k]=$v;
	}

  \@c;
}





# Set cookies returned from server responding to $request_uri.
# The request is needed to configure any defaults as per RFC 6525
#
method set_cookies($request_uri, @cookies){

  Log::OK::TRACE and log_trace __PACKAGE__. " set_cookies";

  # Parse the request_uri
  #
  my ($scheme, $authority, $path, $query, $fragment) =
  $request_uri =~ m|(?:([^:/?#]+):)?(?://([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?|;

  Log::OK::TRACE and log_trace __PACKAGE__. " authority: ". $authority;

  # Parse the authority into userinfo, host and port
  my ($user, $password, $host, $port)=
    $authority =~  m|(?:([^:]+)(?::([^@]+))@){0,1}([^:]+)(?::(\d+)){0,1}|x;

  $port//=80;
  Log::OK::TRACE and log_trace __PACKAGE__. " url host: ".$host;
  Log::OK::TRACE and log_trace __PACKAGE__. " url port: ".$port;
  Log::OK::TRACE and log_trace __PACKAGE__. " url user: ".$user;
  Log::OK::TRACE and log_trace __PACKAGE__. " url password: ".$password;





  my $time=time-$tz_offset; #Cache time. Make referced to GMT

  # Iterate over the cookies supplied
  for my $c_ (@cookies){
    say "";
    my $c=$self->decode_set_cookie($c_);
    say Dumper $c;
    sleep 1;

    # Reject the cookie if secure and scheme is not secure
    #
    $scheme ne "https" and next if $c->[COOKIE_SECURE];

    # Reject if same site is specified but secure is not
    #
    $c->[COOKIE_SECURE] or next if $c->[COOKIE_SAMESITE];

    # Reject if __Host and __Secure prefixed names used but secure is not
    #
    $c->[COOKIE_SECURE] or next if $c->[COOKIE_NAME] =~ m/^__Secure-|^__Host-/;





    # Flag indicating this cookie hasnt't expired but will not be stored
    # outside of this 'session'
    #
    my $current_session_only=not ($c->[COOKIE_MAX_AGE] or $c->[COOKIE_EXPIRES]);

    if(defined $c->[COOKIE_MAX_AGE]){

      Log::OK::TRACE and log_trace "max age set: $c->[COOKIE_MAX_AGE]";
      for($c->[COOKIE_MAX_AGE]){
        if($_<=0){
          $c->[COOKIE_EXPIRES]=0; # set to min time
        }
        else{
          $c->[COOKIE_EXPIRES]=$time+$c->[COOKIE_MAX_AGE]; 
          $c->[COOKIE_PERSISTENT]=1;
        }
      }
    }

    # Use expiry if exclusivly provided
    elsif(defined $c->[COOKIE_EXPIRES] and not defined $c->[COOKIE_MAX_AGE]){
      for($c->[COOKIE_EXPIRES]){
        $c->[COOKIE_PERSISTENT]=1;
        #parse the date and store in the same field

      }
    }
    else{
      $c->[COOKIE_PERSISTENT]=undef;
      $c->[COOKIE_EXPIRES]=$time+400*24*3600; #Mimic chrome for maximum date
    }

    Log::OK::TRACE and log_trace "Expiry set to: $c->[COOKIE_EXPIRES]";

    # Check the expiry date of the cookie. Only applicable if there is max age
    # or expires value set
    #
    my $expired=
      not($current_session_only)
      && ($c->[COOKIE_EXPIRES]<=$time);


    # Use the host as domain if none specified

    # Process the domain of the cookie. set to default if no explicitly set
    say $c->[COOKIE_DOMAIN];
    say scalar reverse $host;
    my $rhost=scalar reverse $host;

    if($c->[COOKIE_DOMAIN]){
      # DO a public suffix check on cookies. Need to ensure the domain for the cookie is NOT a suffix
      my $ps=$self->suffix(scalar reverse $c->[COOKIE_DOMAIN]);#scalar reverse $c->[COOKIE_DOMAIN]);
      my $hi=$self->highest_cookie_domain(scalar reverse $c->[COOKIE_DOMAIN]);

      say "SUFFIX: $ps";
      say "highest: $hi";

      # need to ensure the cookie domain is a sub string of highest possible
      unless(0==index scalar reverse($hi), $c->[COOKIE_DOMAIN]){ 
        Log::OK::TRACE and log_trace "Domain is public suffix. reject";
        next 
      }

      # Domain is stored in reverse for better matching performance
      #$c->[COOKIE_DOMAIN]=scalar reverse $c->[COOKIE_DOMAIN];

      if(0==index $rhost, $c->[COOKIE_DOMAIN]){ 
        # Domain must be at least substring (parent domain).
        $c->[COOKIE_HOST_ONLY]=undef;
      }
      else{
        # Ignore cookie. Attempting to set a cookie for a sub domain
        Log::OK::TRACE and log_trace __PACKAGE__."::set_cookie domain invalid";
      }
    }
    else{
      # Cookie is only accesssable from the same host
      # Set domain to the request host
      $c->[COOKIE_HOST_ONLY]=1;
      $c->[COOKIE_DOMAIN]=$rhost
    }

    # Process path. default is request url if not provided
    # set default path  as per 5.1.4
    #
    $c->[COOKIE_PATH]//="";
    say Dumper $c;
    Log::OK::TRACE and log_trace "Set cookie path is ".  Dumper $c;
    sleep 1;
    if( length($c->[COOKIE_PATH])==0 or  substr($c->[COOKIE_PATH], 0, 1) ne "/"){
      # Calculate default
      if(length($path)==0 or substr($path, 0, 1 ) ne "/"){
        $path="/";
      }
      
      # Remove right / if present
      if(length($path) >1){
        my @parts=split "/", $path;
        pop @parts;
        $c->[COOKIE_PATH]=join "/", @parts;
      }
      else {
        $c->[COOKIE_PATH]=$path;
      }
    }

    my $index;
    my $found;



    # Cookie is validated at this point. Set the creation time

    # Set Creation time
    $c->[COOKIE_CREATION_TIME]=$time;
    Log::OK::TRACE and log_trace __PACKAGE__."::set_cookie creation time: $c->[COOKIE_CREATION_TIME]";

    # Perform a binary search on the domain property of the cookie to find insert position
    #

    $c->[COOKIE_KEY]="$c->[COOKIE_DOMAIN] $c->[COOKIE_PATH] $c->[COOKIE_NAME]";
    Log::OK::TRACE and log_trace __PACKAGE__."::set_cookie key: $c->[COOKIE_KEY]";
    $index=search_string_left $c->[COOKIE_KEY], \@_cookies;

  
    $found=$index<@_cookies  && ($_cookies[$index][COOKIE_KEY] eq $c->[COOKIE_KEY]);


    # Process the Set cookie
    #
    if($found and $c->[COOKIE_EXPIRES]<$time){
      # Found but expired. Delete the cookie
      Log::OK::TRACE and log_trace __PACKAGE__. " found cookie and expired";
      splice @_cookies, $index, 1;
    }
    elsif($found){
      # Update existing
      #
      Log::OK::TRACE and log_trace __PACKAGE__. " found cookie. Updating";

      # Update creation time of new cookie to match the old cookie
      $c->[COOKIE_CREATION_TIME]=$_cookies[$index][COOKIE_CREATION_TIME];
      $_cookies[$index]=$c;
    }
    elsif($c->[COOKIE_EXPIRES]<$time){
      #Cookie not found and expired

      Log::OK::TRACE and log_trace __PACKAGE__. " no existing cookie, but new expired. Do nothing";

    }
    else {
      # Add  cookie. Push if no cookies, splice if already cookies
      #
      Log::OK::TRACE and log_trace __PACKAGE__. " new cookie name. adding";
      unless(@_cookies){
        push @_cookies, $c;
      }
      else{
        splice @_cookies, $index,0, $c;
      }
    }
  }
}

# Retrieves the cookies by name, for the $request_uri in question. The actual
# cookies returned are subject to filtering of the user agent conditions.
#
# Referer url is used in selecting cookies for ssame site access
# Policy is a hash of keys modifiying behaviour 
#   eq action=> follow      Like a user clicking a link
#               resource    user agent loading a resource (ie image )
#               top         Manually typing an address or clicking a shortcut
#               api         Make as an api call, which is a resource call also?
#
method get_cookies($name, $request_uri, $referer_uri, $action=""){
  # Cookies are stored sorted in ascending reverse dns order. parse the URI to get the domain
  #
  # Parse the uri
  my ($scheme, $authority, $path, $query, $fragment) =
  $request_uri =~ m|(?:([^:/?#]+):)?(?://([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?|;

  my ($user, $password, $host, $port)=$authority =~  m|(?:([^:]+)(?::([^@]+))@){0,1}([^:]+)(?::(\d+)){0,1}|x;

  $port//=80;
  my $sld=scalar reverse $self->highest_cookie_domain($host);
  $host=scalar reverse $host;

  # Parse the uri
  my ($rscheme, $rauthority, $rpath, $rquery, $rfragment) =
  $request_uri =~ m|(?:([^:/?#]+):)?(?://([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?|;

  my ($ruser, $rpassword, $rhost, $rport)=$authority =~  m|(?:([^:]+)(?::([^@]+))@){0,1}([^:]+)(?::(\d+)){0,1}|x;

  $rhost=scalar reverse $rhost;
  
  #Start search at the second level domain, ?
  
  ####
  # Search the list from the highest domain down.
  # Start of each of matching with search of sorted domain names
  # iterates over the following items until the domain key, substring no longer matches

  # SAME SITE TESTING
  my $same_host=($rscheme eq $scheme) && ($rauthority eq $authority);

  # Finds the first domain string matching.  The database is searched by the
  # KEY field, which is DOMAIN PATH NAME. The domain is in reverse order so
  # the host name (also reversed) can be used as a prefix which allows a simple 
  # stirng le comparison in the binary search
  #
  my $index=search_string_left $sld, \@_cookies;

  Log::OK::TRACE and log_trace __PACKAGE__. " index is: $index"; 
  Log::OK::TRACE and log_trace Dumper \@_cookies;
  Log::OK::TRACE and log_trace  "looking for host: $sld";

  # Iterate through all cookies until the domain no longer matches
  #
  local $_;
  my $time=time;
  my @output;
  my $process=1;
  my $path_ok=1;
  my $run;
  
  # If $name is empty, we are doing a query for all cookies for this domain/path
  my $any_name=!$name;
  my $time_now=time; 
  while( $index<@_cookies){
    $_=$_cookies[$index];
    # Cookies are sorted by domain. If the domain is not a prefix match
    # we consider the search finished. Actual domain testing is done 
    # if the prefix matches
    #

    # Domains are stored 'reversed'. That means prefixes will always come first.
    # When a  domain no longer matches as a prefix then we know the search can stop
    last if index $sld, $_->[COOKIE_DOMAIN];


    # Need an exact match, not a domain match
    ++$index and next if $sld ne $_->[COOKIE_DOMAIN]  and $_->[COOKIE_HOST_ONLY];
    Log::OK::TRACE and log_trace "Hostonly and host eq domain passed";


    # Secure cookie  and secure channel.
    #
    ++$index and next if $_->[COOKIE_SECURE] and $scheme ne "https";
    Log::OK::TRACE and log_trace "secure and scheme eq https passed";

    # Skip this cookies if the action is classed as api and not as a 
    # browing http request
    #
    ++$index and next if $_->[COOKIE_HTTPONLY] and $action eq "api";
    Log::OK::TRACE and log_trace "action passed";


    # Name match Lets see if the cookie name is a match. If so process the
    # expiry immediately. the $any_name flag allows all cookies for a domain to
    # be extracted
    #
    Log::OK::TRACE and log_trace __PACKAGE__. " cookie:". Dumper $_;
    if($any_name or $_->[COOKIE_NAME] eq $name){
      # Found a matching cookie.
      Log::OK::TRACE and log_trace "NAME OK";
      # Process expire
      if($_->[COOKIE_EXPIRES] <= $time){
        # Expired, remove it from the list
        #
        Log::OK::TRACE and log_trace "cookie under test expired. removing";
        splice @_cookies, $index, 1;
        next;
    }

      # Test if we really want to send the cookie to the domain based on use action


      # Check same site?
      # Strict => User agent only send cookie if the referer is of the same domain
      #           Or if the address is typed into the address bar
      #
      # Lax   =>  Clicking a link and the user navigating to a site from an third party is is ok 
      #            However accessing a resource from a thirdparty site the cookie is not sent
      #
      # None  =>   Cookie is always sent for
      #
      if($_->[COOKIE_SECURE]){
        my $ok=1;
        # Same site cookie processing only applicable to secure cookies
        #
        unless($_->[COOKIE_SAMESITE]){
          # Not set Treat as lax
          $ok&&= !defined($referer_uri) || $same_host ||( $action eq "follow");
        }
        if($_->[COOKIE_SAMESITE] eq "Strict"){
          # only select this cookie if the referer is of same origin as target
          # or if the referer is undefined
          # eg if following a link (clicking on anchor), loading a image/resource or entering address
          $ok&&= !defined($referer_uri) || $same_host;
        }
        elsif($_->[COOKIE_SAMESITE] eq "Lax"){
          # Like String but send cookie when following link from third party site
          $ok&&= !defined($referer_uri) || $same_host || ($action eq "follow");
          
        }
        elsif($_->[COOKIE_SAMESITE] eq "None"){
          # Send cookie all the time
          
        }
        else{
        }

        # Goto next cookie if same site failed
        ++$index and next unless $ok;
      }


      
      # Process path matching as per section 5.1.4 in RFC 6265
      #
      $path||="/";    #TODO find a reference to a standard or rfc for this
      Log::OK::TRACE and log_trace "PATH: $path";
      Log::OK::TRACE and log_trace "Cookie PATH: $_->[COOKIE_PATH]";
      if($path eq $_->[COOKIE_PATH]){
        $path_ok=1;
      }
      elsif (substr($_->[COOKIE_PATH], -1, 1) eq "/"){
        # Cookie path ends in a slash?
        $path_ok=index($path, $_->[COOKIE_PATH])==0      # Yes, check if cookie path is a prefix
      }
      elsif(substr($path,length($_->[COOKIE_PATH]), 1) eq "/"){
        $path_ok= 0==index $path, $_->[COOKIE_PATH];
      }
      else {
         # Not a  path match
         $path_ok=undef;
      }
      Log::OK::TRACE and log_trace "Path ok: $path_ok";

      ++$index and next unless $path_ok; 

        
      #Update last access time
      $_->[COOKIE_LAST_ACCESS_TIME]=$time_now;
      Log::OK::TRACE and log_trace "Pushing cookie";
      push @output, $_;

    }
    $index++;
  }
   
  say "OUTPUT COOKIE: ", Dumper \@output;
  # Sort the output as recommended by RFC 6525
  #  The user agent SHOULD sort the cookie-list in the following
  #     order:
  #
  #     *  Cookies with longer paths are listed before cookies with
  #        shorter paths.
  #
  #     *  Among cookies that have equal-length path fields, cookies with
  #        earlier creation-times are listed before cookies with later
  #        creation-times.

  # The cookies are are stored in ascending lexigraphical order, which is opposite to 
  # the longest path. So we just reverse the array.
  #
  # Then we actually sort by creation time in assecnding order
  #
  @output=sort {$b->[COOKIE_CREATION_TIME] <=> $a->[COOKIE_CREATION_TIME]} reverse @output;
  \@output;
}

# Returns the serialized cookies for transmition to  the server matching
# against the request uri, the current uri Much like the javscript
# document.cookie method, except the the url and actions are needed for
# searching
method encode_cookie($request_uri, $referer_uri=undef, $action=undef){
  my $cookies=$self->get_cookies("",  $request_uri, $referer_uri, $action);
  return unless @$cookies;
  my $value= join "; ", map { "$_->[COOKIE_NAME]=$_->[COOKIE_VALUE]"} @$cookies;
  #TODO: URL encode?

}


# Server side 
# ===========
# Add a cookie to the jar with little validation
method add_cookie ($cookie){

}

# Encode matching cooki into a cookie string
method encode_set_cookie ($cookie){
	Log::OK::DEBUG and log_debug "Serializing set cookie";	
  #my $self=shift;

	my $cookie= "$cookie->[COOKIE_NAME]=$cookie->[COOKIE_VALUE]";			#Do value
	for my $index (COOKIE_MAX_AGE, COOKIE_DOMAIN, COOKIE_PATH, COOKIE_SAMESITE){	#Do Attributes
		for($cookie->[$index]){
			$cookie.="; $names[$index]=$_" if defined;			#Only defined attribues are added
		}
	}
	
	for($cookie->[COOKIE_EXPIRES]){
		if(defined){
			my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) =gmtime $cookie->[COOKIE_EXPIRES];
			$cookie.="; Expires=$days[$wday], $mday $months[$mon] ".($year+1900) ." $hour:$min:$sec GMT";
		}
	}

	$cookie.="; Secure" if defined $cookie->[COOKIE_SECURE];				#Do flag attributes
	$cookie.="; HTTPOnly" if defined $cookie->[COOKIE_HTTPONLY];

	Log::OK::DEBUG and log_debug "$cookie";
	$cookie;

}

#Returns a newly created cookie struct from a Set-Cookie string
#
method decode_set_cookie{
 say "INPUT: ". join ", ", @_;
  # $string, converter
	my $key;
	my $value;
	my @values;
	my $first=1;

  my @fields=split /;\s*/, $_[0];
  #Value needs to be the first field 
	($values[1], $values[2])=split "=", shift(@fields), 2;

	for(@fields){
		($key, $value)=split "=", $_, 2;
    $key=lc $key;
    say "key: $key value: ".$value//"";

    # Look up the value key value pair
    # unkown values are stored in the undef => 0 position
    $values[$reverse{$key}]=$value//1;
	}

  # nuke unkown value
  $values[0]=undef;

  # Fix the date. Date is stored in seconds internally
  #
  #say $values[COOKIE_EXPIRES];
  my ($wday_key, $mday, $mon_key, $year, $hour, $min, $sec, $tz)=
        $values[COOKIE_EXPIRES]=~/([^,]+), (\d+)\-([^-]{3})\-(\d{4}) (\d+):(\d+):(\d+) (\w+)/;

  if(70<=$year<=99){
    $year+=1900;
  }
  elsif(0<=$year<=69){
      $year+=2000;
  }
  else{
    #year as is
  }

  $values[COOKIE_DOMAIN]=~s/\.$//;
  $values[COOKIE_DOMAIN]=~s/^\.//;
  $values[COOKIE_DOMAIN]=scalar reverse $values[COOKIE_DOMAIN];

   #TODO other date checking...

  ###############################
  # say "wday-key : $wday_key"; #
  # say "mday : $mday";         #
  # say "mon_key: $mon_key";    #
  # say "year: $year";          #
  # say "hour: $hour ";         #
  # say "min:$min";             #
  # say "sec:$sec";             #
  # say "tz: $tz";              #
  ###############################

  $values[COOKIE_EXPIRES]=timegm_modern($sec, $min, $hour, $mday, $months{$mon_key}, $year);
  \@values;
}

#Returns key value pairs flattened in list
#
sub decode_cookie{
	my @values;
  my ($key, $value);

	for(split ";", $_[0]=~tr/ //dr){
		($key,$value)= split "=";
    push @values,$key,$value;
	}
	\@values;
}

method dump_cookies{
  \@_cookies;
}


1;
