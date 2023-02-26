use ExtUtils::MakeMaker;

WriteMakefile(
	NAME              => 'uSAC::HTTP',
	VERSION_FROM      => 'lib/uSAC/HTTP.pm',
	MIN_PERL_VERSION  => '5.36.0',		
	EXE_FILES	=> ['script/usac'],
	
	PREREQ_PM         => {
		EV		=> 0,
		AnyEvent 	=> 0,
		'Digest::SHA1' 	=> 0,
		JSON		=> 0,
		'Cpanel::JSON::XS'     	=> 0,
		enum	    	=> 0,

		"Hustle::Table" => "0.5.5",	#Bug fix for updating default matcher
		"uSAC::IO"	=> 0,
		"IO::FD"	=> "0.2.0",
    "Error::Show"=>0,
		"Socket::More"	=> 0,
		"uSAC::MIME"	=> 0,
    "Sub::Middler"=>0,
    "File::Meta::Cache"=>0
		

		"Crypt::JWT"	=> 0,
		"Log::ger"	=> 0,
		"Log::ger::Output::Screen" => 0,
		"Log::OK"	=> "v0.1.5",
		"URI"		=> 0,
		"URL::Encode"	=> 0,
		"URL::Encode::XS" =>0,
    "Data::UUID"=>0

	},
	ABSTRACT_FROM     => 'lib/uSAC/HTTP.pod', # retrieve abstract from docs
	AUTHOR            => 'Ruben Westerberg',
	LICENSE           => 'mit',
);
