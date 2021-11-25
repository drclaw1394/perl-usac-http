sub {
	my $OUT=$_[0];
	$$OUT.=<<~EOF;
	A basic template with no control structures but with variable interpolation
	@_

	FOOTER GOES HERE
	EOF
}
