#!/usr/bin/perl
#
# TextSleuth v1.2
# Written by Derek Pascarella (ateam)
#
# A utility to recursively scan a folder of files for a dynamic, custom-encoded text string.

# Include necessary modules.
use strict;
use File::Find;
use Time::HiRes 'time';
use List::MoreUtils qw(uniq);

# Set version.
my $version = 1.2;

# Define input parameters.
my ($byte_length, $pattern_file, $search_path, $wildcards, $ignore) = @ARGV;

# Default wildcard count to zero.
if(!defined($wildcards))
{
	$wildcards = 0;
}

# Store program usage.
my $usage = "Usage: text_sleuth <parameters>\n\n";
  $usage .= "Required Parameter 1: Encoded character byte length (e.g., 1, 2).\n";
  $usage .= "Required Parameter 2: Path of pattern file.\n";
  $usage .= "Required Parameter 3: Path of folder to recursively scan (or single file).\n";
  $usage .= "Optional Parameter 4: Number of wildcard bytes in between encoded characters (e.g., 1, 2).\n";
  $usage .= "                      Use zero (0) if no wildcards needed, but Optional Parameter 5 is needed.\n";
  $usage .= "Optional Parameter 5: Comma-separated list of file extensions to ignore (e.g., sfd,adx,pvr).";

# Status message.
print "\nTextSleuth v" . $version . "\n";
print "Written by Derek Pascarella (ateam)\n\n";

# Perform input validation.
if($byte_length eq "" && $pattern_file eq "" && ($search_path eq "" || $search_path eq "."))
{
	die($usage . "\n\n");   
}
elsif($byte_length !~ /^\d+$/)
{
	die("Specified character byte length is invalid, must be whole number greater than zero.\n\n" . $usage . "\n\n");
}
elsif($wildcards !~ /^\d+$/)
{
	die("Specified wildcard count is invalid, must be whole number zero or greater.\n\n" . $usage . "\n\n");
}
elsif(!-R $pattern_file)
{
	die("Cannot read specified pattern file.\n\n" . $usage . "\n\n");
}
elsif(-d $pattern_file)
{
	die("Specified pattern file is a folder, cannot read.\n\n" . $usage . "\n\n");
}
elsif(!-R $search_path)
{
	die("Cannot read specified search path.\n\n" . $usage . "\n\n");
}

# Store contents of search pattern file.
open my $pattern_fh, '<', $pattern_file or die $!;
my $pattern_line = <$pattern_fh>;
close $pattern_fh;

# Remove extraneous whitespace from pattern text.
$pattern_line =~ s/^\s+|\s+\$//g;
$pattern_line =~ s/\s+/ /g;

# Split the cleaned pattern into individual elements.
my @pattern = split / /, $pattern_line;
my $pattern_length = scalar(@pattern);
my $unique_pattern_count = scalar(uniq(@pattern));

# Calculate how far apart each meaningful byte is in the chunk, considering wildcards.
my $stride = $byte_length + $wildcards;
my $pattern_span = $byte_length + ($pattern_length - 1) * $stride;

# Status message.
print "> Character byte length: " . $byte_length . "\n\n";
print "> Wildcard byte count: " . $wildcards . "\n\n";
print "> Search pattern: " . $pattern_line . "\n\n";

# Initialize array to store all file paths that will be scanned.
my @files;

# If the path is a single file, add it to the list directly.
if(-f $search_path)
{
	push(@files, $search_path);
}
# Otherwise, recursively find all files in the specified directory.
else
{
	find(sub { push @files, $File::Find::name if -f }, $search_path);
	
	# Apply optional file extension filtering.
	if(defined $ignore && $ignore ne '')
	{
		my @extensions = split /,/, $ignore;

		@files = grep {
			my $f = $_;
			!grep { $f =~ /\.$_\z/i } @extensions
		} @files;
	}
}

# Status message.
print "> Initiating scan process against " . scalar(@files) . " file" . ($#files == 0 ? "" : "s") . "...\n\n";

# Initialize counters and start the timer.
my $total_size = 0;
my $match_count = 0;
my $start_time = time();

# Loop through each file in the list.
for my $file (@files)
{
	# Get the size of the file. Skip if too small to match.
	my $size = -s $file;
	next unless defined $size && $size >= $pattern_span;

	# Read file content into memory as raw binary.
	open my $binary_fh, '<:raw', $file or next;
	read $binary_fh, my $data, $size;
	close $binary_fh;

	# Add to the total size counter.
	$total_size += $size;
	my $first_match = 1;

	# Slide across the file byte-by-byte to test for matches.
	for(my $i = 0; $i <= $size - $pattern_span; $i ++)
	{
		# Extract a chunk equal in size to the total pattern span.
		my $chunk = substr($data, $i, $pattern_span);

		# Compute which offsets in the chunk to actually examine.
		my @positions;

		for my $j (0 .. $#pattern)
		{
			push @positions, $j * $stride;
		}

		# Extract meaningful byte sequences based on the positions.
		my @groups;

		foreach my $position (@positions)
		{
			push @groups, substr($chunk, $position, $byte_length);
		}

		# Quick check to skip if unique count doesn't match.
		next if scalar(uniq(@groups)) != $unique_pattern_count;

		# Perform full match logic using a byte mapping hash.
		my %byte_map;
		my $valid = 1;

		for my $j (0 .. $#pattern)
		{
			my $id = $pattern[$j];
			my $value = $groups[$j];
			
			if(!exists $byte_map{$id})
			{
				$byte_map{$id} = $value;
			}
			elsif($byte_map{$id} ne $value)
			{
				$valid = 0;

				last;
			}
		}

		# Valid match found, display it.
		if($valid)
		{
			$match_count ++;

			# Print file name only once per file (first match).
			if($first_match)
			{
				# Correct forward slash for Windows.
				if($^O =~ "MSWin")
				{
					my $file_display_name = ($file =~ s/\//\\/gr);

					print "> " . $file_display_name . "\n";
				}
				else
				{
					print "> " . $file . "\n";
				}

				$first_match = 0;
			}

			# Status message.
			printf "  - Offset 0x%X (decimal %d)\n", $i, $i;
			print "    " . (unpack 'H*', $chunk) . "\n";
		}
	}
}

# Calculate total elapsed time.
my $elapsed = time() - $start_time;

# Status message.
print "\n" if $match_count > 0;
print "> Scan complete. Found " . $match_count . " match" . ($match_count == 1 ? "" : "es") . ".\n\n";
print "> Total scanned size: $total_size bytes\n\n";
printf "> Time elapsed: %.2f seconds\n\n", $elapsed;