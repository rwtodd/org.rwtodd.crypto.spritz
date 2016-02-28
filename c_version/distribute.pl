#!/usr/bin/perl

# ******************************************************************
# distribute.pl -- distribute work acrosss worker processes
# ******************************************************************
use v5.020;
use Getopt::Std;

sub HELP_MESSAGE {
        select(STDERR);
	say "Usage: distribute.pl [options] [file1] [file2]...";
	say "  -h       Display this help message.";
	say "  -p prog  The program (and static arguments) to run.";
	say "  -j n     The number of jobs to spawn.";
	exit(2);
}

sub VERSION_MESSAGE {
	say STDERR "distribute.pl v1.0  (c) 2016 Richard Todd";
}

sub splitby {
  my $n = shift;
  my $each = int(scalar(@_)/$n+0.5);
 
  my @ans = ();
 
  my $idx = 0;
  for (1..$n-1) {
	my @nxt = splice(@_,0,$each);
	push(@ans, \@nxt);
  }
  push @ans, \@_;
  return \@ans;
}

my %options;
getopts('hp:j:', \%options) or &HELP_MESSAGE;

if($options{h}) { &HELP_MESSAGE }

my $njobs  = $options{j};
if($njobs == 0) { $njobs = 1 }

my $jlist = splitby($njobs,@ARGV);

for my $l (@$jlist) {
  next if scalar(@$l) == 0;
  my $pid = fork();
  if ($pid == 0) {
     exec( split(/\s+/,$options{p}), @$l);
  }
}

while(wait() != -1) { }
