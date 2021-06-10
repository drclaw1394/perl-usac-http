use ExtUtils::MakeMaker;
#BEGIN{ $ENV{AUTHOR} and require CPAN::Meta and CPAN::Meta->import();  };

WriteMakefile(
	NAME              => 'uSAC::HTTP::Server',
	VERSION_FROM      => 'lib/uSAC/HTTP/Server.pm',
	PREREQ_PM         => {
		AnyEvent => 5,
		'Digest::SHA1' => 2,
		'JSON::XS'     => 3,
	},
	ABSTRACT_FROM     => 'lib/uSAC/HTTP/Server.pm', # retrieve abstract from module
	AUTHOR            => 'Ruben Westerberg',
	LICENSE           => 'perl',
	PL_FILES          => {},
	clean             => {},
);
