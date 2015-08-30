package TSM::Crypt;
#   .   .   .   .   .   .   .   .   .   .   .   .   .   .   .   . 
#  .                                                              . 
#  .                   'T S M : : C r y p t'                      . 
#  .                                                              . 
#  .  Author: Eric de Hont eric-github@hobiho.nl                  . 
#  .                                                              . 
#  .  Date:   Tue Oct 16 15:46:34 CED 2012                        . 
#  .                                                              . 
#  .  Short description:                                          . 
#  .                                                              . 
#  .       Obfuscate the password a bit.                          . 
#  .                                                              . 
#   .   .   .   .   .   .   .   .   .   .   .   .   .   .   .   . 

use strict;
use warnings;

our $VERSION = "1.00";

use base 'Exporter';

our @EXPORT = qw(t_enc t_dec);

# Don't read this!
# Back slowly away from this code!

sub t_enc { 
  my $secret = shift; 
  my ($filler1,$filler2); 
   $secret = join ('',map {chr(int(rand(126-33))+33)} 1..50) .
						 $secret .
             join ('',map {chr(int(rand(126-33))+33)} 1..50);
  $secret = pack("u",$secret); 
	$secret =~ s/\n//g; # Keep everyting in one line.
  return $secret; 
} 
 
sub t_dec { 
  my $secret = shift; 
  my $decrypted = unpack(chr(ord("a") + 19 + print ""),$secret); 
  $decrypted =~ s/^(.{50})(.+?)(.{50})$/$2/; 
  return $decrypted; 
}

# Ok, now you've done it.
# You're in a right mess you are. NOW EAT THIS SCRIPT AND SWALLOW IT!

# No, seriously, perhaps one day someone will rewrite this script
# in assembler and compile it, but even then some clever person will
# be able to reverse engineer what it does.

1;
