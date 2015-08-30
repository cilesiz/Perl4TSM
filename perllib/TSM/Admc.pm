package TSM::Admc;

use strict;
use warnings;
use Exporter;
use Carp;
use Sys::Hostname;
use TSM::Creds;

our (@ISA, %EXPORT_TAGS, @EXPORT_OK, @EXPORT, $VERSION);
@ISA= ("Exporter");
%EXPORT_TAGS = (
                 all => [ qw(set_alt_passwordfile admin_name vrfy_creds admc admc_hashed q_admc_data q_admc_info) ],
               );
@EXPORT_OK   = ( @{ $EXPORT_TAGS{all} } );
@EXPORT      = qw(admc admc_hashed q_admc_data q_admc_info q_admc_simple);
$VERSION=1.00;

=head1 TSM::Admc

TSM::Admc - Perl interfaces for TSM (dsmadmc)

=head1 Author

Eric de Hont - eric-github@hobiho.nl

=head1 SYNOPSYS

use TSM::Admc;

=head2 Discription

A library of functions to facilitate communication with TSM, while keeping the complexity of authentication out of sight.

=cut

# Select appropriate config manager
## Change these lines for your config
my %configmanager = ( aix0123 => 'tsmcfg1',
                      sun4567 => 'tsmcfg2');
my $hostname = hostname;

# Choose the configmanager based on hostname
my $cfgmgr = $configmanager{$hostname};

# Verify availability of dsmadmc
chomp(my $DSMADMC = `which dsmadmc`) or croak "Error: dsmadmc not found.\n";
croak "dsmadmc not executable." unless -X $DSMADMC;

my $admc_auth = q{};  # Empty string

my $alt_passwordfile = undef;

=head2 Functions

=head3 set_alt_passwordfile()

    set_alt_passwordfile("$ENV{HOME]/.TSMCredsSpecial");

(Optional)

Use an alternative passwordfile, previously created with C<tsmcreds -f ~/TsmCredsSpecial>.

You probably won't need this, but it's there, just in case.

=cut

# Function to set alternative credentials file
sub set_alt_passwordfile{
    $alt_passwordfile = shift;
    croak "Password file $alt_passwordfile not found or unreadable.\n"
        unless -r $alt_passwordfile;
}

my ($TC,$id,$pa);

# Point to new credentials file
sub tsm_auth{
    my %args = ();
    %args = ( file => $alt_passwordfile ) if $alt_passwordfile;
    $TC = TSM::Creds->new(%args);
    croak "No valid credentials found. Run tsmcreds first.\n" unless $TC->ok;
    ($id,$pa) = ($TC->id,$TC->pa);
    $admc_auth = qq{ -id=$id -pa=$pa };
    return $id;
}

=head3 vrfy_creds

  my $id = vrfy_creds()

(Optional)

Use this funtion to check the authentication if needed. The function breaks when the passwordfile is not valid or the key in that file is expired or locked. Otherwise it returns the ID (key) that will be used while communicating with TSM.

Run this command after specifying an alternative passwordfile or to check the authentication at the start of some longer running script.

The functions admc and admc_hashed call this function implicitly, so unless you want to check authentication implicitly there usually is no need to call this function from your script.

=cut

sub vrfy_creds{
    if(! ref($TC)){ # No creds yet
        tsm_auth(); # Get/set the credentials
    }
    else{
        # New password file?
        if ($alt_passwordfile and $alt_passwordfile ne $TC->file){

            # Read the alternate passwordfile
            $TC->read($alt_passwordfile);

            croak "No valid credentials found in $alt_passwordfile.\n" unless $TC->ok;
            ($id,$pa) = ($TC->id,$TC->pa);

            # New user for DSMADMC
            $admc_auth = "-id=$id -pa=$pa";
        }
    }

    # Query ADMINISTRATOR from cfgmgr
    # Croak on common errors
    my @errors = grep {/^(AN.....[WE]|ANS1051I)/} qx/$DSMADMC -se=$cfgmgr $admc_auth "q admin $id f=d"/ ;
    croak "Account locked? Password expired?\n" . map {"Errors: $_"} @errors . "\n"
        if @errors;

    return $id;
}

=head3 The admc-subroutines

=head3 admc

@admc_output = admc( %options );

Just plain dsmadmc with authentication. Does nothing special just returns an array from the command. Returns an array reference in scalar context.

Use this where admc_hashed (the other admc-subroutine, see below) isn't flexible enough.

Usage:

 @admc_output = admc(
    {                                            # Defaults to...
     instance => 'tsmcfg',                       # local config manager
     route    => [qw/tsms001 tsms002/],          # empty string
     options  => '-comma',                       # -tab -dataonly=yes
     command  => 'select * from administrators', # q status
    }
 );

All options are... optional!

Make I<options> an empty string (q{}) (not undef!) to obtain the normal (TSM-manager like)
output with column headings. A real challenge to parse, though!

I<instance> is a valid TSM instance name, defaults to local config manager

I<route> is a valid instance name, a servergroup, a comma separated string of those, or a reference to an array that contains any of those.

 {...
 route => 'tsms001,tsms002'
 ...}

 my @myroute = ('tsms001', 'tsms002');

 and later:
 {...
 route => \@myroute
 ...}

 my $route = 'tsms001,tsms002'

 and later:
 {...
 route => $route
 ...}

Example:

 my @admc_output =   admc(
                            {
                                instance => q{tsms010},
                                command  => q{q ev * *},
                                options  => q{},
                            }
                         );

 print Dumper(\@admc_output);

 $VAR1 = [
          'IBM Tivoli Storage Manager',
          'Command Line Administrative Interface - Version 6, Release 3, Level 0.0',
          '(c) Copyright by IBM Corporation and other(s) 1990, 2011. All Rights Reserved.',
          '',
          'Session established with server TSMS010: AIX',
          '  Server Version 6, Release 3, Level 4.0',
          '  Server date/time: 08-04-2014 23:34:30  Last access: 08-04-2014 22:55:29',
          '',
          'ANS8000I Server command: \'q ev * *\'',
          '',
          'Scheduled Start          Actual Start             Schedule Name     Node Name         Status   ',
          '--------------------     --------------------     -------------     -------------     ---------',
          '08-04-2014 00:00:00                               BACKUP_0000       CLIENT050072      Missed   ',
          '08-04-2014 00:00:00      08-04-2014 00:50:49      BACKUP_0000       CLIENT072329      Completed',

 8<-----

          '08-04-2014 22:30:00      08-04-2014 22:30:07      BACKUP_2230       CLIENT072300      Completed',
          '08-04-2014 23:00:00      08-04-2014 23:32:16      BACKUP_2300       CLIENT072344      Started  ',
          '',
          'ANS8002I Highest return code was 0.',
          ''
        ];

=cut

sub admc{
    vrfy_creds();
    my ($arg_ref) = @_;
    # Set defaults...
    #              If option given...            Use option             Else default
    my $instance = exists $arg_ref->{instance} ? $arg_ref->{instance} : $cfgmgr;
    $instance    = $cfgmgr unless defined $instance;
    my $route    = exists $arg_ref->{route}    ? $arg_ref->{route}    : undef;
    my $command  = exists $arg_ref->{command}  ? $arg_ref->{command}  : 'q status';
    my $options  = exists $arg_ref->{options}
                 ? $arg_ref->{options} || '-displ=tab -dataonly=yes'
                 : q{};

    # If route option is a reference to an array, turn it into a string
    if (ref($route)){
        for (ref($route)) {
            # You can route your command to an array of instances/server groups
            if      (/ARRAY/) {$route = join(',',@$route) . ':' }
            else    {croak "Routing argument to admc is of wrong type: $_\n" }
        }
    }
    else{
        $route = (defined $route)?"$route:":'';
    }
    my @output = qx/$DSMADMC $admc_auth $options -se=$instance \"$route$command\"/
        or croak "$DSMADMC failed: $!\n";
    chomp(@output);
    if (wantarray){
        return @output;
    }
    else{
        return \@output;
    }
}


=item admc_hashed()

=over

admc_hashed returns three references:

=item $msgs_ref

 A reference to an array containing all TSM-messages.

 A reference to an array of the TSM-messages, not the output of your 'real' command.
 Each line is prepended with the name of the instance that generated the message.

=item $data_ind_ref

 A reference to a hash containing the output of the TSM-command, split on a primary key.
 This hash will be blank in case TSM overwrites the primary key of the oupput.
 In repetative output, like q node, the node name is the primary key.

 The structure is {Instance => {ITEM => {Attribute => Value}}}

 There is a special key I<_order> in every hash of each ITEM that holds an array
 with all atributes in the original order.

=item $data_seq_ref

 A reference to a hash containing the data output of the TSM-command, serialized in an
 array. Usefull for commands like q ev * *

 The structure is {Instance[{Attribute => Value..%Attributex => Valuex} , {...}]}

 There is a special key I<_order> in every hash the array has, that holds an array
 with all atributes in the original order.

=back

Example:

my $command =
    qq/select node_name,platform_name,domain_name,contact from nodes where node_name like 'AIX12%'/;

 my($msgs_ref, $data_indexed_ref, $data_sequential_ref)
    = admc_hashed({
                                                 # Defaults to...
     instance => 'tsmcfg',                       # local config manager
     route    => [qw/tsms010 tsms011/],          # undef
     command  => $command,                       # q status
    });

 # print errors and warnings
 print map {"$_\n"} grep {/ANR....(W|E)/} @$msgs_ref;

 # print data structure
 print Dumper($data_indexed_ref);

 Dumper wil give an impression of how the data structure looks like.

=head2 data_indexed

 $VAR1 = {
     'TSMS011' => {
                  'AIX142A_APPL002' => {
                                         'CONTACT' => '=A= AIX142A_APPL002',
                                         'DOMAIN_NAME' => '3_ORACLE',
                                         '_order' => [
                                                       'NODE_NAME',
                                                       'PLATFORM_NAME',
                                                       'DOMAIN_NAME',
                                                       'CONTACT'
                                                     ],
                                         'PLATFORM_NAME' => 'TDP Oracle AIX',
                                         'NODE_NAME' => 'AIX142A_APPL002'
                                       },

 8<----

     _invalid' => 0,
                  'AIX11Z6_APPL1' => {
                                       'CONTACT' => '=P=',
                                       'DOMAIN_NAME' => '2_ORACLE',
                                       '_order' => [
                                                     'NODE_NAME',
                                                     'PLATFORM_NAME',
                                                     'DOMAIN_NAME',
                                                     'CONTACT'
                                                   ],
                                       'PLATFORM_NAME' => '',
                                       'NODE_NAME' => 'AIX11Z6_APPL1'
                                     }
         },
     _command' => '[tsmcfg]tsms010,tsms011:select node_name,platform_name,domain_name,contact from nodes where node_name like \'AIX1%\''
   };

 Note that the key I<_command> retains the given command, and the key I<_order> keeps track of the original order of the hash keys.

 A special key I<_invalid> gets set when the primary key gets overwritten. In that case the other hash ref I<data_seq> should be used.

Note: Key I<_type>, with value 'sequential' or 'indexed' is recently added and missing from the above print.

=head2 Example code to loop through this indexed hash:

 foreach my $instance (sort grep {!m/\A_/} keys %$data_ref){
    print "Instance: $instance\n";
    foreach my $node (sort grep {!m/\A_/} keys %{$data_ref->{$instance}}){
        print "\tNode: $node\n";
        foreach my $field (@{$data_ref->{$instance}{$node}{_order}}){
          print "\t\tField: $field; \tValue: $data_ref->{$instance}{$node}{$field}\n";
        }
    }
 }

=head2 data_seq

$VAR1 = {
          'TSMS011' => [
                         {
                           'DOMAIN_NAME' => '3_GENERIC',
                           'CONTACT' => '=T= AIX14Y2',
                           '_order' => [
                                         'NODE_NAME',
                                         'PLATFORM_NAME',
                                         'DOMAIN_NAME',
                                         'CONTACT'
                                       ],
                           'NODE_NAME' => 'AIX14Y2',
                           'PLATFORM_NAME' => 'AIX'
                         },

 8<-----

                         {
                           'DOMAIN_NAME' => '3_GENERIC',
                           'CONTACT' => '=T= AIX14Z2',
                           '_order' => [
                                         'NODE_NAME',
                                         'PLATFORM_NAME',
                                         'DOMAIN_NAME',
                                         'CONTACT'
                                       ],
                           'NODE_NAME' => 'AIX14Z2',
                           'PLATFORM_NAME' => 'AIX'
                         },
                       ],
          '_invalid' => 0,
          '_command' => '[tsmcfg]tsms010,tsms011:select node_name,platform_name,domain_name,contact from nodes where node_name like \'AIX1%\''
        };

Note: Key _type, with value 'sequential' or 'indexed' is recently added and missing from the above print.

=head2 Example code to loop through this sequential hash

 foreach my $instance (sort grep {!m/\A_/} keys %$data_seq_ref){
     print "\nSEQ - Instance: $instance\n";
     foreach my $node_ref (@{$data_seq_ref->{$instance}}){
         print "\t@{$node_ref->{_order}}\n";
         print map {"\t\tField: $_\tValue: $node_ref->{$_}\n"} @{$node_ref->{_order}};
         print "\n";
     }
 }

=head2 Show command sent to TSM

 print "Command:", $data_seq_ref->{_command}, "\n";

=cut

## Creates a hash for each item in the output per instance, like a
## hash for each node in the case of q node
## For data with no apparrant structure, like q ev * * we need to provide
## a way to create an array of hashes. One hash for each record.
sub admc_hashed{

    # Check authentication first
    vrfy_creds();

    my ($arg_ref) = @_;

    # Set defaults...
    #              If option given...            Use option             Else default
    my $instance = exists $arg_ref->{instance} ? $arg_ref->{instance} : $cfgmgr;
    $instance    = $cfgmgr unless defined $instance;
    my $route    = exists $arg_ref->{route}    ? $arg_ref->{route}    : undef;
    my $command  = exists $arg_ref->{command}  ? $arg_ref->{command}  : 'q status';

    # $route can be a reference to an array
    # In that case: dereference it and turn it into a string
    # like 'instance_a,instance_b:'.
    if (ref($route)){
        for (ref($route)) {
            # You can route your command trough an array of instances/server groups
            if      (/ARRAY/) {$route = join(',',@$route) . ':' }
            else    {croak "Second argument to admc is of wrong type: $_\n" }
            }
    }
    else{
        $route = (defined $route)   ?   "$route:"
                                    :   q{};
    }

    # Use list format to enable simple conversion to hash
    my $options = '-displ=list -dataonly=yes';

    # Keep TSM-messages and actual output data separate
    my (@msgs,%data_ind,%data_seq);

    # Keep track of which instance we are currently processing
    my $current_instance = $instance;

    # Signal start of new record.
    my $newrec = 1;

    # First fieldname of record. For instance node_name in select * from nodes
    # Used as key
    my $item; # First fieldname of record. For instance node_name in select * from nodes

	# Escape double quotes in command
	$command =~ s{ (["]) }{\\$1}gxms;

    # Open filehandle with dsmadmc
    open (my $admc_fh, '-|', qq/$DSMADMC $admc_auth $options -se=$instance "$route$command"/)
        or croak "$DSMADMC failed: $!\n";

    # Remember the command that created the output
    my $i = defined $instance ? $instance : q{};
    $data_ind{_command} = "[$i]$route$command";
    $data_seq{_command} = "[$i]$route$command";

    # Mark each type of hash to make it easy to recognize
    $data_ind{_type} = "indexed";
    $data_seq{_type} = "sequential";

    # Mark invalidity of the output in a special field
    # Empty = ok
    $data_ind{_invalid} = 0;
    $data_seq{_invalid} = 0;

    # hash to collect TSM-output of an instance sequentially
    # one block at a time
    my %field_val;

    # Read output from TSM one line at a time
    while (<$admc_fh>){
        chomp;

        # Empty line
        if (/^$/){
            # Repeating blocks of output are separated by an empty line.
            $newrec=1;

            # Collect data for data_seq
            if (keys %field_val){
                push @{$data_seq{$current_instance}},{ %field_val };
                %field_val = ();
            }
            next;
        }

        # Next instance
        if (/^ANR1687I/){ # ANR1687I Output for command 'Q NODE p* ' issued against server THEP401 follows:
            /^.*server (\S*) follows/;
            $current_instance = $1;
            next;
        }

        # Output of instance completed
        if (/^ANR1688I/){ # ANR1688I Output for command 'Q NODE p* ' issued against server THEP401 completed.
            if (keys %field_val){
                push @{$data_seq{$current_instance}},{ %field_val };
                %field_val = ();
            }
            $current_instance = $instance;
            next;
        }

        # Keep TSM-message apart from data
        if (/^AN\w\d{4}\w/){
            push @msgs,"$current_instance: $_";
            next;
        }

        # Insert an extra hash level based on the value of the first attribute
        # of each item in the output
        my ($field,$value) = m{
                                \A         # Start of string
                                 \s*       # Skip white space
                                 (.+?)     # Goes in $field
                                 :\s       # Separator
                                 (.+)?     # Goes in $value Could be empty, so '?'
                                \z         # End of string
                                }xsm;

        # Undefined value become empty string
        $value = defined($value) ? $value : q{};

        # If the above regex matched, then...
        if (defined $field){
            if (exists $field_val{$field}){
                $data_seq{_invalid} = 
                    "Not Ok: Duplicate in \"$current_instance, $field, $field_val{$field}\"";
				# Blank the hash
                foreach my $key (keys %data_seq){
                    next if $key =~ m{ \A _ .* }xms; # Skip info keys
					delete $data_seq{$key}; 
				}
            }
            push @{$field_val{_order}},$field;
            $field_val{$field} = $value;

            # Use value of the first key seen as a new hash level.
            # For instance: the value of node_name in select * from nodes.
            if ($newrec){
                # Use value of the first key seen as a new hash level for
                # data_ind
                # For instance: the value of node_name in select * from nodes.
                $item = $value;
                $newrec = 0;
            }

            next if $data_ind{_invalid};

            # Check to see if field already seen. You loose data otherwise!
            # If so, use data_seq
            if (exists $data_ind{$current_instance}->{$item}{$field}){
                $data_ind{_invalid} = "Not OK: Duplicate in \"$current_instance => $item,$field\"";
                foreach my $key (keys %data_ind){
                    next if $key =~ m{ \A _ .* }xms; # Skip info keys
                    delete $data_ind{$key};
                }
            }

            push @{$data_ind{$current_instance}->{$item}{_order}},$field
				unless $data_ind{_invalid};
            $data_ind{$current_instance}->{$item}{$field} = $value
				unless $data_ind{_invalid};
        }
    }
    return (\@msgs,\%data_ind,\%data_seq);
}

################################################

=head2 Subroutine to query hash while avoiding referencing complexity

=head3 q_data_ref[,$instance[,index[,field]]])

The output hashes contain a key I<_type> with which the q_output function determines what to do.

=head3 Query the instances that gave a valid response (both indexed and sequential output types)

@instances = q_output($hash_ref)

=cut

sub q_admc_data{
  my $hash_ref = $_[0] or croak "q_admc_data needs at least a hash_ref as argument.\n";

  # Hashref should be at least a real hash
  croak 'q_admc_data: Not a valid hash received.' unless ref($hash_ref) eq 'HASH';

  # Hash should be either indexed or sequential
  croak 'q_admc_data: Neither indexed or sequential...'
    unless $hash_ref->{_type} =~ m{(indexed|sequential)};

  # Provide easy check of validity of hash
  return -1 if $hash_ref->{_invalid};

  # Indexed or sequential
  my $type = $hash_ref->{_type};

  for (scalar @_) {
    # Return instances
    if      ($_ == 1) {return grep { !/ \A _ /xms } keys %{$_[0]} }

    # If $_[1] starts with underscore return value of key
    # otherwise return indexes or refs to sequential output
    elsif   ($_ == 2) {
                           my $instance = $_[1];
                           if ( $_[1] =~ / \A _ /xms){
                               my @info_keys = grep { / \A (_.+) /xms } keys %{$_[0]};
                               croak "No such key: \"$_[1]\".\n\tValid keys are: @info_keys.\n"
                                   unless exists $_[0]->{$_[1]};
                               return $_[0]->{$_[1]};
                           }
                           else{
                              # Indexed: return list of keys (for examples node_name)
                              # Sequential: return number of sequences
                              for ($type) {
                                if      (/indexed/) { 
                                                        # Return sorted list of keys
                                                        my @list_of_keys = keys %{$hash_ref->{$instance}};
                                                        return sort @list_of_keys;
                                                    }
                                elsif   (/sequential/) {
                                                           # Return highest index #
                                                           return 0 .. $#{$hash_ref->{$instance}};
                                                       } 
                                else    { die "No valid type: $type \n" }
                                }
                           }
                      }
    elsif   ($_ == 3) {
                          my $instance = $_[1];
                          my $item     = $_[2];
                          for ($type) {
                              if (/indexed/) {
                                  # Indexed: return list of keys of the current item
                                  # in the original order.
                                  return @{$hash_ref->{$instance}{$item}{_order}};
                                             }
                              elsif (/sequential/) {
                                  # Return list of keys of the current item
                                  # in the original order.
								  # N.B.: Item must be numerical! (array index)
								  croak qq{Third argument ($item) should have been }
								        . qq{numerical for sequental type TSM-data.}
									    if $item =~ /\D/;
                                  return @{$hash_ref->{$instance}[$item]{_order}};
                                                   }
                              else  { die "No valid type: $type \n" }
                              }
                      }
    elsif   ($_ == 4) {
                          my $instance = $_[1];
                          my $item     = $_[2];
                          my $field    = $_[3];
                          for ($type) {
                            if      (/indexed/) {
                                                # Indexed: return value of field
                                                return $hash_ref->{$instance}{$item}{$field}
                                            }
                            elsif   (/sequential/) {
                                                   # Sequential: return value of field
                                                   return $hash_ref->{$instance}[$item]{$field}
                                               }
                            else    { die "No valid type: $type \n" }
                            }
                      }
    else    {print "Not implemented.\n" }
    }
}

=head2 Function to query some info about the hash 

=head3 q_admc_info($hash_ref)

Each hash contains some informational keys which could be usefull.

Query them with q_admc_info()

=head3 Example

 print q_admc_info($hash_ref)
  _invalid:
            0
  _type:
            indexed
  _command:
            [tsmcfg]tsms010,tsms011:select node_name,platform_name,domain_name,contact from nodes where node_name like 'AIX1%'

 print q_admc_info($hash_ref,'type')
    indexed

=cut

sub q_admc_info{
    my $hash_ref = shift;
    croak "ERROR: Argument must be a hash.\n" unless ref $hash_ref eq "HASH";

    my $info_key =  shift;

    # Return all info_keys with values
    return map {"$_:\n\t$hash_ref->{$_}\n"} grep { m{ \A _ }xms }keys %$hash_ref unless $info_key;

    # prepend underscore if omitted
    $info_key =~    s{  \A
                        [^_]   # First character not _
                        .*
                     }
                     {_$&}xms; # Put _ in front of string

    # Create list of valid keys
    my @info_keys = grep { / \A (_.+) /xms } keys %$hash_ref;
    croak "No such key: \"$info_key\".\n\tValid keys are: @info_keys.\n"
                                   unless exists $hash_ref->{$info_key};
    return $hash_ref->{$info_key};
}

sub q_admc_simple{
    # q_adsm_simple(array_ref,hash_ref,hash_ref)
    # return a simple list like:
    # <instance>:<index>:<attribute>:<value>
    # ...
    # #<instance>:ANR1234E ...
    # ...
    # Where <index> is numerical for output without primary key.

    # first argument
    my $msgs_ref = shift or croak "q_adsm_simple: Not enough arguments\n";
    croak 'q_adsm_simple: First parameter should be array reference.' unless ref($msgs_ref) eq 'ARRAY';

    # second argument
    my $data_ind_ref = shift or croak "q_adsm_simple: Not enough arguments\n";
    croak 'q_adsm_simple: Second parameter should be hash reference.' unless ref($data_ind_ref) eq 'HASH';

    # third argument
    my $data_seq_ref = shift or croak "q_adsm_simple: Not enough arguments\n";
    croak 'q_adsm_simple: Second parameter should be hash reference.' unless ref($data_seq_ref) eq 'HASH';

    # When data_ind_ref invalid, work with data_seq_ref
    my $ind_invalid = q_admc_info($data_ind_ref,'_invalid');
    my $data_ref = $ind_invalid ? $data_seq_ref : $data_ind_ref;

    my @simple;
    foreach my $instance (q_admc_data($data_ref)){
        foreach my $index (q_admc_data($data_ref,$instance)){
            my @sequences = q_admc_data($data_ref,$instance,$index);
            foreach my $field (@sequences){
                my $value = q_admc_data($data_ref,$instance,$index,$field);
                push @simple,"$instance:$index:$field:$value";
            }
        }
    }

    # Keep only errors 
    @$msgs_ref = grep {/ANR\d{4}[E]/} @$msgs_ref;

    # Append the TSM messages.
    push @simple, map {"#$_"} @$msgs_ref;
    push @simple, '# Command: '. q_admc_info($data_ref,'_command');

    # Ugly, but more easy to print. So it keeps life simple.
    $_ .= "\n" foreach @simple;
    if (wantarray){
        return @simple;
    }
    else{
        return \@simple;
    }
}

1;
