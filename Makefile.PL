use ExtUtils::MakeMaker;

WriteMakefile(
	NAME              => 'uSAC::HTTP',
	VERSION_FROM      => 'lib/uSAC/HTTP.pm',
	MIN_PERL_VERSION  => '5.36.0',		
	EXE_FILES	=> ['script/usac-http-server'],
	
	PREREQ_PM         => {
		EV		=> 0,
		AnyEvent 	=> 0,
		'Digest::SHA1' 	=> 0,
		JSON		=> 0,
		'Cpanel::JSON::XS'     	=> 0,

		"Hustle::Table" => "0.5.5",	# Bug fix for updating default matcher
		"uSAC::IO"	=> 0,           # IO streaming abstraction
		"IO::FD"	=> "0.3.7",       # pread/pwrite
    "Error::Show"=>"0.3.0",     # 0.3.0 for default import of 'context'
		"Socket::More"	=> "0.5.1", # passive/listen socket specification
		"uSAC::MIME"	=> 0,         # MIME database
    "Sub::Middler"=>0,          # Subroutine middleware linking
    "File::Meta::Cache"=>0,     # Meta data and open file cache
    "Export::These"=>"v0.1.1",         # Simpler export and reexport
    "Import::These"=>"v0.1.2",  
    "HTTP::State"=>"v0.1.1",    # Cookies
    "constant::more"=> "v0.3.0",
		"Log::OK"	=> "v0.2.1",
		"Template::Plex"	=> "v0.7.0",
    "uSAC::FastPack" => 0,      # Message brokering
    "Text::Table"=>0,


		
    "Object::Pad"=> "0.808",
		"Crypt::JWT"	=> 0,
		"Log::ger"	=> 0,
		"Log::ger::Output::Screen" => 0,
		"URI"		=> 0,
		"URL::Encode"	=> 0,
		"URL::Encode::XS" =>0,
    "Data::UUID"=>0,
    "Data::Dump"=>0,
    "Data::Dump::Color"=>0,
    "Time::Local"=>0,
    "Exception::Class::Base"=>0


	},
	ABSTRACT_FROM     => 'lib/uSAC/HTTP.pod', # retrieve abstract from docs
	AUTHOR            => 'Ruben Westerberg',
	LICENSE           => 'mit',
);
