sub {
        my $OUT=$_[0];	#alias the buffer

        $$OUT.=include "./experiments/do.pl", @_;

        my $time=time;

        $$OUT.=<<~EOF;
                Welcome to $_->{location} at this time: $time;
                some more text
        EOF
}
