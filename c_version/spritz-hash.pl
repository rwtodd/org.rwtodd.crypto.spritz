#!/usr/bin/perl 

use v5.22.0;

use IO::Handle;
use IPC::Open2 qw(open2);
use IO::Poll qw(POLLIN POLLHUP);
use Getopt::Std;
use Cwd qw(abs_path);

sub HELP_MESSAGE() {
	select(STDERR);
	say "Usage: spritz-hash.pl [options] [file1] [file2]...";
	say "  -h    Display this help message.";
	say "  -s n  Set the hash size to n bits.";
	say "  -j n  Run n hashes at once.";
	exit(2);
}

sub VERSION_MESSAGE() {
	say STDERR "spritz-hash version 1.0  (c) 2016 Richard Todd";
}

sub print_help() {
	&VERSION_MESSAGE();
	&HELP_MESSAGE();
}

my $errCount = 0;

sub handle_output {
  no warnings qw(experimental::smartmatch);
  my $ln = shift;
  my ($status, $msg) = $ln =~ /^(OK|ER) ?(.*)$/;
  given($status) {
	when("OK") { say $msg unless (!$msg);      }
	when("ER") { say STDERR $msg; $errCount++; }
  } 
}

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Start of Script
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

my %options;
getopts('hs:j:', \%options) or HELP_MESSAGE();

print_help() if $options{h};

my $njobs = $options{j} - 1;
if($njobs < 0) { $njobs = 0; }

my $hsize = $options{s} + 0;
if($hsize == 0) { $hsize = 256; }

my $poll = IO::Poll->new();

my @readers;
my @writers;

my $processor = abs_path($0);
$processor =~ s:/[^/]*$:/spritz-hash.exe:;

for my $idx (0..$njobs) {
	my ($reader, $writer) = (IO::Handle->new, IO::Handle->new);
	$writer->autoflush(1);
	open2($reader, $writer, $processor,"-s$hsize");
	push @readers, $reader;
	push @writers, $writer;
	$poll->mask($reader => POLLIN | POLLHUP);
}

while( scalar $poll->handles() ) {
  $poll->poll();
  for my $idx (0..$njobs) { 
	if( $poll->events($readers[$idx]) & (POLLIN|POLLHUP) ) {
		&handle_output( $readers[$idx]->getline() );
		my $next = shift @ARGV;
		if($next) {
			$writers[$idx]->say($next);
                } else {
			$poll->remove($readers[$idx]);
			$readers[$idx]->close();
			$writers[$idx]->close();
		}	
        }
  }
}

# non-zero exit if we had errors
if($errCount > 0) {
  exit(1);
}
