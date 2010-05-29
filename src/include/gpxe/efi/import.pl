#!/usr/bin/perl -w

use File::Spec::Functions qw ( :ALL );
use File::Find;
use File::Path;
use FindBin;
use strict;
use warnings;

sub try_import_file {
  my $gpxedir = shift;
  my $edkdirs = shift;
  my $filename = shift;

  # Skip everything except headers
  return unless $filename =~ /\.h$/;
  print "$filename...";

  my $outfile = catfile ( $gpxedir, $filename );
  foreach my $edkdir ( @$edkdirs ) {
    my $infile = catfile ( $edkdir, $filename );
    if ( -e $infile ) {
      # We have found a matching source file - import it
      print "$infile\n";
      open my $infh, "<$infile" or die "Could not open $infile: $!\n";
      ( undef, my $outdir, undef ) = splitpath ( $outfile );
      mkpath ( $outdir );
      open my $outfh, ">$outfile" or die "Could not open $outfile: $!\n";
      my @dependencies = ();
      my $licence;
      my $guard;
      while ( <$infh> ) {
	# Strip CR and trailing whitespace
	s/\r//g;
	s/\s*$//g;
	chomp;
	# Update include lines, and record included files
	if ( s/^\#include\s+[<\"](\S+)[>\"]/\#include <gpxe\/efi\/$1>/ ) {
	  push @dependencies, $1;
	}
	# Check for BSD licence statement
	if ( /^\s*THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE/ ) {
	  die "Licence detected after header guard\n" if $guard;
	  $licence = "BSD3";
	}
	# Write out line
	print $outfh "$_\n";
	# Apply FILE_LICENCE() immediately after include guard
	if ( /^\#define\s+_?_\S+_H_?_$/ ) {
	  die "Duplicate header guard detected in $infile\n" if $guard;
	  $guard = 1;
	  print $outfh "\nFILE_LICENCE ( $licence );\n" if $licence;
	}
      }
      close $outfh;
      close $infh;
      # Warn if no licence was detected
      warn "Cannot detect licence in $infile\n" unless $licence;
      warn "Cannot detect header guard in $infile\n" unless $guard;
      # Recurse to handle any included files that we don't already have
      foreach my $dependency ( @dependencies ) {
	if ( ! -e catfile ( $gpxedir, $dependency ) ) {
	  print "...following dependency on $dependency\n";
	  try_import_file ( $gpxedir, $edkdirs, $dependency );
	}
      }
      return;
    }
  }
  print "no equivalent found\n";
}

# Identify edk import directories
die "Syntax $0 /path/to/edk2/edk2\n" unless @ARGV == 1;
my $edktop = shift;
die "Directory \"$edktop\" does not appear to contain the EFI EDK2\n"
    unless -e catfile ( $edktop, "MdePkg" );
my $edkdirs = [ catfile ( $edktop, "MdePkg/Include" ),
		catfile ( $edktop, "IntelFrameworkPkg/Include" ) ];

# Identify gPXE EFI includes directory
my $gpxedir = $FindBin::Bin;
die "Directory \"$gpxedir\" does not appear to contain the gPXE EFI includes\n"
    unless -e catfile ( $gpxedir, "../../../include/gpxe/efi" );

print "Importing EFI headers into $gpxedir\nfrom ";
print join ( "\n and ", @$edkdirs )."\n";

# Import headers
find ( { wanted => sub {
  try_import_file ( $gpxedir, $edkdirs, abs2rel ( $_, $gpxedir ) );
}, no_chdir => 1 }, $gpxedir );
