#!/usr/bin/perl 

use v5.22.0;

use IO::Handle;
use IPC::Open2 qw(open2);
use IO::Poll qw(POLLIN POLLHUP);
use Getopt::Std;
use Cwd qw(abs_path);

sub HELP_MESSAGE() {
	select(STDERR);
	say "Usage: spritz-crypt.pl [options] [file1] [file2]...";
	say "  -h     Display this help message.";
	say "  -d     Decrypt files rather than encrypt.";
	say "  -o dir Output files in `dir` rather than the input's directory.";
	say "  -p pwd Set the password.";
	say "  -j n   Run n operations at once.";
	exit(2);
}

sub VERSION_MESSAGE() {
	say STDERR "spritz-crypt version 1.0  (c) 2016 Richard Todd";
}

sub print_help() {
	&VERSION_MESSAGE();
	&HELP_MESSAGE();
}

# determine the target name, given:
#    the source name, 
#    whether we are decrypting or not, and 
#    whether we should change the output dir or not.
sub target_name {
   my ($tgt,$dec,$odir) = @_;	

   # step 1, change extension
   if($dec) {
        # strip .spritz, add .unenc if it didn't end in spritz
	if(($tgt =~ s/\.spritz$//) == 0)  {
		$tgt .= ".unenc";  
	}
   } else {
	# add .spritz when encrypting
	$tgt .= ".spritz"; 
   } 

   # step 2, switch output dir
   if($odir) {
	$tgt =~ s:^.*[^\\]/::;
	$tgt = "$odir/$tgt";
   }
   return $tgt;
}

my $errCount = 0;  #  GLOBAL keep track of errors, to set exit code 

sub handle_output {
  no warnings qw(experimental::smartmatch);
  my $ln = shift;
  my ($status, $msg) = $ln =~ /^(OK|ER) ?(.*)$/;
  given($status) {
	when('OK') { say $msg unless (!$msg);      }
	when('ER') { say STDERR $msg; $errCount++; }
  } 
}

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Start of Script
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

my %options;
getopts('hdo:p:j:', \%options) or HELP_MESSAGE();

&print_help() if $options{h};

my $njobs = $options{j} - 1;
if($njobs < 0) { $njobs = 0; }

my $pw = $options{p};
if($pw eq '') { &print_help(); }

my $e_or_d = $options{d} ? "D" : "E";

my $poll = IO::Poll->new();

my @readers;
my @writers;

my $processor = abs_path($0);
$processor =~ s:/[^/]*$:/spritz-crypt.exe:;

for my $idx (0..$njobs) {
	my ($reader, $writer) = (IO::Handle->new, IO::Handle->new);
	$writer->autoflush(1);
	open2($reader, $writer, $processor, "-p","$pw");
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
		        my $tgt = &target_name($next,$options{d},$options{o});	
			$writers[$idx]->say("$e_or_d $next $tgt") or $errCount++;
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
