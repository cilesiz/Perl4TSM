package TSM::Creds;
#   .   .   .   .   .   .   .   .   .   .   .   .   .   .   .   .  
#  .                                                              .  
#  .                   'T S M : : C r e d s'                      .  
#  .                                                              .  
#  .  Author: Eric de Hont eric-github@hobiho.nl                  .  
#  .                                                              .  
#  .  Date:   Tue Oct 16 15:46:34 CED 2012                        .  
#  .                                                              .  
#  .  Short description:                                          .  
#  .                                                              .  
#  .        Manipulate TSM-credential objects                     .  
#  .                                                              .  
#   .   .   .   .   .   .   .   .   .   .   .   .   .   .   .   .  
#
# To do: A function to store invalid password message in the
#        creds file flagging it as invalid. That way clients
#        can prevent the administrator from becoming locked.
#
# Mon Dec 23 10:41:28 CET 2013
#  Changed UNIX permission of password file to "-rw-------"
#
use strict;
use warnings;
use TSM::Crypt;

our $VERSION = "1.00";

=head1 NAME

TSM::Creds - Manipulate TSM-credential objects

=head1 DESCRIPTION

This is an object-oriented library which can read obfuscated TSM-credentials from a file, as well as create them to store in such a file.

=head2 Methods

=head3 new

	my $TC = TSM::Creds->new();
	my $TC = TSM::Creds->new( file => $credsfile );

Instantiates an object which holds a TSM-id and its password, if it can be read from ${HOME}/.TSMCreds. If I<file> is given an alternative file is used. If no password file could be opened, I<ok> will be 0 and I<error> will contain something like 'A file or directory in the path name does not exist.' Use the script I<tsmcreds> or the method I<update> to create such a file.

=cut

sub new {
  my ($class, %args) = @_;
	my $idpa;
	my $self = bless({}, $class);
	$self->{id} = '';
	$self->{pa} = '';
	$self->{file} = exists $args{file} ? $args{file} : "$ENV{HOME}/.TSMCreds";
	if (open CREDS,'<',$self->{file}){
		chomp ($idpa = (<CREDS>));
		close CREDS;
		($self->{id},$self->{pa}) = split /:/,t_dec($idpa);
		$self->{error} = '';
	  $self->{ok} = ($self->{id} && $self->{pa}) ? 1 : 0;
	}else{
		$self->{error} = $!;
	  $self->{ok} = 0;
	}
	return $self;
}

=head3 ok

	$TC->ok();

Return the I<status> (OK or not OK, 1 or 0) of the object. Possible statuses: 0 means id, password or both are B<not> present, 1 means both id and password B<are> present.

=cut

sub ok {
  my $self = shift;
	return $self->{ok};
}

=head3 error

	$TC->error();

Return the last error raised by a method. For instance the error raised while trying to read or create a password-file. Retrieving the error automatically clears it. Check the I<error> when I<ok> returns 0.

=cut

sub error {
  my $self = shift;
	my $error = $self->{error};
	$self->{error} = '';
	return $error;
}

=head3 file

	$TC->file;
	$TC->file($filename);

Get or set the filename of the object. Returns I<filename>.

=cut

sub file {
  my $self = shift;
	$self->{file} = shift if @_;
	return $self->{file};
}

=head3 id

	$TC->id();
	$TC->id('ab34cd');

Get or set the userid of the object. Returns the I<ID>.

=cut

sub id {
  my $self = shift;
#	print ">Id: .@_.\n"; ##############
	$self->{id} = shift if @_;
	$self->{ok} = ($self->{id} && $self->{pa}) ? 1 : 0;
  return "$self->{id}";
}

=head3 pa

	$TC->pa();
	$TC->pa($password);

Get or set the password of the object. Returns the I<password>.

=cut

sub pa {
  my $self = shift;
#	print ">Pa: .@_.\n"; ###########
	$self->{pa} = shift if @_;
	$self->{ok} = ($self->{id} && $self->{pa}) ? 1 : 0;
  return "$self->{pa}";
}

=head3 update

	$TC->update();
	$TC->update($passwordfile);

Update or create the passwordfile. Returns I<ok>.

=cut

sub update {
  my ($self, %args) = @_;
	$self->{file} = $args{file} if exists $args{file};
	return unless $self->{ok}; # id and pa not both available
	my $old_umask = umask;
		umask 0077 or die "Unable to set safe umask 0077. $!\n";
	open CREDS,'>',$self->{file} or die "Unable to open $self->{file}: $!\n";
	print CREDS t_enc($self->{id}.':'.$self->{pa}) or die "Unable to write to $self->{file}: $!\n";
	close CREDS;
  chmod 0600,$self->{file} or die "Unable to set safe permissions 0600 on password file. $!\n";
  umask $old_umask;
	$self->{error} = '';
	$self->{ok} = ($self->{id} && $self->{pa}) ? 1 : 0;
	return $self->{ok};
}

=head3 reset

	$TC->reset();

Clear the credentials of the object.

=cut

sub reset {
 my $self = shift;
 $self->{id} = '';
 $self->{pa} = '';
 $self->{error} = 'Credentials have been cleared.';
 $self->{ok} = 0;
}

=head3 read

	$TC->read();
	$TC->read($passwordfile);

Read the credentials from the passwordfile (after an update). Returns I<ok>.

=cut

sub read {
  my ($self, %args) = @_;
	$self->{file} = $args{file} if exists $args{file};
	if (open CREDS,'<',$self->{file}){
		local $\ = undef;
		chomp (my $idpa = (<CREDS>));
		close CREDS;
		($self->{id},$self->{pa}) = split /:/,t_dec($idpa);
	  $self->{ok} = ($self->{id} && $self->{pa}) ? 1 : 0;
	}else{
		$self->{error} = $!;
	  $self->{ok} = 0;
	}
	return $self->{ok};
}

1;
