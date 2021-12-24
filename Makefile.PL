use ExtUtils::MakeMaker;
#BEGIN{ $ENV{AUTHOR} and require CPAN::Meta and CPAN::Meta->import();  };

WriteMakefile(
	NAME              => 'uSAC::HTTP::Server',
	VERSION_FROM      => 'lib/uSAC/HTTP/Server.pm',
	PREREQ_PM         => {
		EV		=> 0,
		AnyEvent 	=> 0,
		'Digest::SHA1' 	=> 0,
		JSON		=> 0,
		'JSON::XS'     	=> 0,
		enum	    	=> 0,
		"Hustle::Table" => "0.3.0",

		"Crypt::JWT"	=> 0,
	},
	ABSTRACT_FROM     => 'lib/uSAC/HTTP/Server.pm', # retrieve abstract from module
	AUTHOR            => 'Ruben Westerberg',
	LICENSE           => 'mit',
);
