use ExtUtils::MakeMaker;
#BEGIN{ $ENV{AUTHOR} and require CPAN::Meta and CPAN::Meta->import();  };

WriteMakefile(
	NAME              => 'uSAC::HTTP',
	VERSION_FROM      => 'lib/uSAC/HTTP.pm',
	PREREQ_PM         => {
		EV		=> 0,
		AnyEvent 	=> 0,
		'Digest::SHA1' 	=> 0,
		JSON		=> 0,
		'JSON::XS'     	=> 0,
		enum	    	=> 0,
		"Hustle::Table" => "0.3.0",
		"uSAC::SIO"	=> 0,

		"Crypt::JWT"	=> 0,
	},
	ABSTRACT_FROM     => 'lib/uSAC/HTTP.pod', # retrieve abstract from module
	AUTHOR            => 'Ruben Westerberg',
	LICENSE           => 'mit',
);
