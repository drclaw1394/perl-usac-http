use ExtUtils::MakeMaker;

WriteMakefile(
	NAME              => 'uSAC::HTTP',
	VERSION_FROM      => 'lib/uSAC/HTTP.pm',
	MIN_PERL_VERSION  => '5.32.0',		#for isa operator
	PREREQ_PM         => {
		EV		=> 0,
		AnyEvent 	=> 0,
		'Digest::SHA1' 	=> 0,
		JSON		=> 0,
		'JSON::XS'     	=> 0,
		enum	    	=> 0,
		"Hustle::Table" => "0.5.0",
		"uSAC::SIO"	=> 0,
		"Sys::Sendfile" => 0,
		

		"Crypt::JWT"	=> 0,
		"Log::ger"	=> 0,
		"Log::ger::Output::Screen" => 0,
		"Log::OK"	=> 0,
		"uSAC::MIME"	=> 0

	},
	ABSTRACT_FROM     => 'lib/uSAC/HTTP.pod', # retrieve abstract from docs
	AUTHOR            => 'Ruben Westerberg',
	LICENSE           => 'mit',
);
