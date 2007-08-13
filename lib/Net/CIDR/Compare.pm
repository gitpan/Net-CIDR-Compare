package Net::CIDR::Compare;

use 5.005000;
use strict;
use warnings;
use Carp;
use Net::CIDR;
use Net::Netmask;

$|++;

require Exporter;
use AutoLoader;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use Net::CIDR::Compare ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	
);

our $VERSION = '0.01';

sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.

    my $constname;
    our $AUTOLOAD;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    croak "&Net::CIDR::Compare::constant not defined" if $constname eq 'constant';
    my ($error, $val) = constant($constname);
    if ($error) { croak $error; }
    {
	no strict 'refs';
	# Fixed between 5.005_53 and 5.005_61
#XXX	if ($] >= 5.00561) {
#XXX	    *$AUTOLOAD = sub () { $val };
#XXX	}
#XXX	else {
	    *$AUTOLOAD = sub { $val };
#XXX	}
    }
    goto &$AUTOLOAD;
}

require XSLoader;
XSLoader::load('Net::CIDR::Compare', $VERSION);

# Preloaded methods go here.

use IO::File;
use File::Temp qw(tempfile tempdir);
use IO::Socket;
use Data::Dumper;

sub new {
  my $invocant = shift;
  my %params = @_;
  my $class = ref($invocant) || $invocant;
  my $cidr_ptr = start_new();
  my $self = { cidr_ptr => $cidr_ptr };
  $self->{print_errors} = 1 if $params{print_errors};
  return bless $self, $class;
}

sub new_list {
  my $self = shift;
  my $list_ptr = setup_new_list($self->{cidr_ptr});
  return $list_ptr;
}

sub remove_list {
  my $self = shift;
  my $list_ptr = shift;
  delete_list($self->{cidr_ptr}, $list_ptr);
}

sub add_range {
  my $self = shift;
  my $list = shift;
  my $ip_range = shift;
  my $skip_check = shift;
  my $array_ref = ();
  if ($skip_check) {
    push @$array_ref, $ip_range;
  }
  else {
    $array_ref = $self->process_ip_range($ip_range) || return 0;
  }
  foreach my $cidr_range (@$array_ref) {
    my ($network, $cidr) = split(/\//, $cidr_range);
    if (!defined($cidr)) {
      $self->{error} = "IP range is malformed [$ip_range].";
      print STDERR $self->{error} . "\n" if $self->{print_errors};
      return 0;
    }
    my $network_decimal = unpack 'N', inet_aton($network);
    save_cidr($list, $network_decimal, $cidr); 
  }
  return 1;
}

sub process_intersection {
  my $self = shift;
  while ($self->get_next_intersection_range()) {
    # do nothing.  this frees C pointers.
  }
  delete $self->{leftover_cidr_processed};
  delete $self->{leftover_cidr_unprocessed};
  delete $self->{expand_cidr};
  my %params = @_;
  $self->{expand_cidr} = $params{expand_cidr};
  my $cidr_ptr = $self->{cidr_ptr};
  dump_intersection_output($cidr_ptr);
}

sub get_next_intersection_range {
  my $self = shift;
  my $cidr_ptr = $self->{cidr_ptr};
  if ($self->{leftover_cidr_processed} && @{$self->{leftover_cidr_processed}}) {
    return shift @{$self->{leftover_cidr_processed}};
  }
  if ($self->{leftover_cidr_unprocessed} && @{$self->{leftover_cidr_unprocessed}}) {
    my $range = shift @{$self->{leftover_cidr_unprocessed}};
    my $cidr_aref = expand_cidr($range, $self->{expand_cidr});
    my $first_expand_range = shift @$cidr_aref;
    if (@$cidr_aref) {
      unshift @{$self->{leftover_cidr_processed}}, @$cidr_aref;
    }
    return $first_expand_range;
  }
  my $range = dump_next_intersection_output($cidr_ptr);
  return unless $range;
  if (defined($self->{expand_cidr})) {
    my ($network, $cidr) = split("/", $range);
    if ($cidr >= $self->{expand_cidr}) {
      return $range;
    }
    else {
      if (($self->{expand_cidr} - $cidr) > 16) {
        my $cidr_aref = expand_cidr($range, 16);
        my $first_slash16 = shift @$cidr_aref;
        my $cidr_aref_first_slash16 = expand_cidr($first_slash16, $self->{expand_cidr});
        my $first_expand_range = shift @$cidr_aref_first_slash16;
        push @{$self->{leftover_cidr_processed}}, @$cidr_aref_first_slash16;
        push @{$self->{leftover_cidr_unprocessed}}, @$cidr_aref;
        return $first_expand_range;
      }
      my $cidr_aref = expand_cidr($range, $self->{expand_cidr});
      my $first_expand_range = shift @$cidr_aref;
      push @{$self->{leftover_cidr_processed}}, @$cidr_aref;
      return $first_expand_range;
    }
  }
  return $range;
}

sub process_ip_range {
  my $self = shift;
  my $ip_range = shift;
  my @octets;
  my $cidr;
  $ip_range =~ s/(\s|\n|\r)+//g;
  if ($ip_range =~ /^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$/) {
    my $ip_start = $1;
    my $ip_end = $2;
    my $ip_start_decimal = unpack 'N', inet_aton($ip_start);
    my $ip_end_decimal   = unpack 'N', inet_aton($ip_end);
    $self->process_ip_range($ip_start) || return 0; # Do this to run further sanity checks
    $self->process_ip_range($ip_end)   || return 0; #
    if ($ip_end_decimal < $ip_start_decimal) {
      $self->{error} = "IP range is malformed [$ip_range]. Range problem.";
      print STDERR $self->{error} . "\n" if $self->{print_errors};
      return 0;
    }
    my @cidr_array = Net::CIDR::range2cidr("$ip_start-$ip_end");
    return \@cidr_array;
  }
  elsif ($ip_range =~ /^(.+)\.(.+)\.(.+)\.([\d\-\[\]\*]+)$/) {
    @octets = ($1, $2, $3, $4);
  }
  elsif ($ip_range =~ /^(.+)\.(.+)\.(.+)\.(.+)\/(\d+)$/) {
    @octets = ($1, $2, $3, $4);
    $cidr = $5 if defined $5;
  }
  else {
    $self->{error} = "IP range is malformed [$ip_range]";
    print STDERR $self->{error} . "\n" if $self->{print_errors};
    return 0;
  }
  my $range_flag = 0;
  for (my $x = 0; $x <= $#octets; $x++) {
    if ($octets[$x] eq "[0-255]") {
      $octets[$x] = "*";
    }
    if ($octets[$x] =~ /^\[(\d+)-(\d+)\]$/ && !defined($cidr)) {
      my $begin_range = $1;
      my $end_range = $2;
      if ($begin_range < 0 || $begin_range > 255 || $end_range < 0 || $end_range > 255 || $begin_range > $end_range) {
        $self->{error} = "IP range is malformed [$ip_range].  Range problem.";
        print STDERR $self->{error} . "\n" if $self->{print_errors};
        return 0;
      }
      if ($range_flag) {
        $self->{error} = "IP range is malformed [$ip_range].  Range values can only be used for one octet.";
        print STDERR $self->{error} . "\n" if $self->{print_errors};
        return 0;
      }
      $range_flag = 1;
    }
    elsif ($octets[$x] =~ /^\d+$/) {
      if ($range_flag) {
        $self->{error} = "IP range is malformed [$ip_range].  Only asterisks can be used after a bracketed range. Example: 10.10.[1-2].*";
        print STDERR $self->{error} . "\n" if $self->{print_errors};
        return 0;
      }
      if ($octets[$x] < 0 || $octets[$x] > 255) {
        $self->{error} = "IP range is malformed [$ip_range].  Range problem.";
        print STDERR $self->{error} . "\n" if $self->{print_errors};
        return 0;
      }
    }
    elsif ($octets[$x] =~ /^\*$/ && !defined($cidr)) {
      # Do nothing
    }
    else {
      $self->{error} = "IP range is malformed [$ip_range]";
      print STDERR $self->{error} . "\n" if $self->{print_errors};
      return 0;
    }
  }
  if (defined($cidr) && ($cidr > 32 || $cidr < 0)) {
    $self->{error} = "IP range is malformed [$ip_range].  Incorrect CIDR notation.";
    print STDERR $self->{error} . "\n" if $self->{print_errors};
    return 0;
  }
  # Passed initial checks

  my %hash;
  if (defined($cidr)) {
    my @range = Net::CIDR::cidr2range($ip_range);
    ($hash{ip_start}, $hash{ip_end}) = split(/-/, $range[0]);
    $hash{ip_start_decimal} = unpack 'N', inet_aton($hash{ip_start});
    $hash{ip_end_decimal}   = unpack 'N', inet_aton($hash{ip_end});
  }
  else {
    for (my $x = 0; $x < 4; $x++) {
      if ($octets[$x] eq '*') {
        $hash{ip_start} .= "0.";
        $hash{ip_end} .= "255.";
      }
      elsif ($octets[$x] =~ /\[(\d+)-(\d+)\]/) {
        $hash{ip_start} .= $1 . ".";
        $hash{ip_end} .= $2 . ".";
      }
      elsif ($octets[$x] =~ /(\d+)/) {
        $hash{ip_start} .= $1 . ".";
        $hash{ip_end} .= $1 . ".";
      }
      else {
        $self->{error} = "Got unexpected IP value [$ip_range]";
        print STDERR $self->{error} . "\n" if $self->{print_errors};
        return 0;
      }
    }
    $hash{ip_start} =~ s/^(.+)\.$/$1/;
    $hash{ip_end}   =~ s/^(.+)\.$/$1/;
  }
  my @cidr_array = range2cidrlist($hash{ip_start}, $hash{ip_end});
  return \@cidr_array;
}

sub expand_cidr {
  my $cidr_range = shift;
  my $level = shift; # Should be 0 thru 32
  die "Invalid CIDR notation [$level]" if ($level < 0 || $level > 32);
 
  my ($network, $cidr) = split("/", $cidr_range);

  my $network_decimal = unpack 'N', inet_aton($network);
  my @result = ();
  if ($cidr >= $level) {
    push @result, $cidr_range;
    return \@result;
  }
  my $num_slices = 2 ** ($level - $cidr);
  for (my $x = 0; $x < $num_slices; $x++) {
    my $add = $x * (2 ** (32 - $level));
    my $smaller_network = inet_ntoa(pack 'N', ($network_decimal + $add));
    push @result, ($smaller_network . "/" . $level);
  }
  return \@result;
}

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Net::CIDR::Compare - Perl extension for blah blah blah

=head1 SYNOPSIS

  use Net::CIDR::Compare;
  blah blah blah

=head1 DESCRIPTION

Stub documentation for Net::CIDR::Compare, created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

Blah blah blah.

=head2 EXPORT

None by default.



=head1 SEE ALSO

Mention other useful documentation such as the documentation of
related modules or operating system documentation (such as man pages
in UNIX), or any relevant external documentation such as RFCs or
standards.

If you have a mailing list set up for your module, mention it here.

If you have a web site set up for your module, mention it here.

=head1 AUTHOR

root, E<lt>root@localdomainE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2007 by root

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.5 or,
at your option, any later version of Perl 5 you may have available.


=cut
