#!/usr/bin/perl
#
# TextSleuth v1.1
# Written by Derek Pascarella (ateam)
#
# A brute-force search utility to identify non-standard text encoding formats.

# Include necessary modules.
use strict;
use MCE::Util;
use File::Find;
use Time::HiRes ("time");
use List::MoreUtils ("uniq");
use Getopt::Long (":config", "no_ignore_case", "no_auto_abbrev");
use threads;
use threads::shared;
use Thread::Queue;

# Supress default error messages.
Getopt::Long::Configure("pass_through");

# Retrieve CPU count.
my $cpu_count = MCE::Util::get_ncpu();

# Set version.
my $version = "1.1";

# Define input parameters.
my ($byte_length, $pattern_file, $search_path, $wildcard, $ignore, $thread_count);

# Store program usage.
my $usage = "Usage: text_sleuth --parameter <value>\n\n";
  $usage .= "Required:\n";
  $usage .= "-l, --length NUM         - Encoded character byte length (e.g., 1, 2)\n";
  $usage .= "-p, --pattern FILE       - Path of pattern file\n";
  $usage .= "-s, --source DIR or FILE - Path of folder to recursively scan (or single file)\n\n";
  $usage .= "Optional:\n";
  $usage .= "-w, --wildcard NUM       - Number of wildcard bytes in between encoded characters (e.g., 1, 2)\n";
  $usage .= "-i, --ignore STR         - Comma-separated list of file extensions to ignore (e.g., sfd,adx,pvr)\n";
  $usage .= "-c, --thread-count NUM   - Number of threads to use (default is CPU core count minus one)";

# Store program header.
my $header = "\nTextSleuth v" . $version . "\n";
  $header .= "Written by Derek Pascarella (ateam)\n\n";

# No options were specified.
if(scalar(@ARGV) == 0)
{
	die($header . "ERROR: No options specified.\n\n" . $usage . "\n\n");
}

# Define our parameters and arguments.
GetOptions(
	"l|length=s" => \$byte_length,
	"p|pattern=s" => \$pattern_file,
	"s|source=s" => \$search_path,
	"w|wildcard=s" => \$wildcard,
	"i|ignore=s" => \$ignore,
	"c|thread-count=s" => \$thread_count
);

# Identify leftover invalid parameters.
my @unknown_options = grep { /^--/ } @ARGV;

if(@unknown_options)
{
	die($header . "ERROR: One or more invalid options specified (" . join(", ", @unknown_options) . ").\n\n" . $usage . "\n\n");
}

# Default wildcard count to zero.
$wildcard = 0 if(!defined $wildcard);

# Set default thread count if none specified.
my $custom_thread_count = 1;

if(!defined $thread_count)
{
	$thread_count = $cpu_count > 1 ? $cpu_count - 1 : 1;

	$custom_thread_count = 0;
}

# Perform input validation.
if($byte_length eq "" && $pattern_file eq "" && ($search_path eq "" || $search_path eq "."))
{
	die($header . $usage . "\n\n");
}
elsif($byte_length !~ /^\d+$/)
{
	die($header . "ERROR: Specified character byte length is invalid, must be whole number greater than zero.\n\n" . $usage . "\n\n");
}
elsif($wildcard !~ /^\d+$/)
{
	die($header . "ERROR: Specified wildcard count is invalid, must be whole number zero or greater.\n\n" . $usage . "\n\n");
}
elsif(!-R $pattern_file)
{
	die($header . "ERROR: Cannot read specified pattern file.\n\n" . $usage . "\n\n");
}
elsif(-d $pattern_file)
{
	die($header . "ERROR: Specified pattern file is a folder, cannot read.\n\n" . $usage . "\n\n");
}
elsif(!-R $search_path)
{
	die($header . "ERROR: Cannot read specified search path.\n\n" . $usage . "\n\n");
}
elsif($thread_count !~ /^\d+$/ || $thread_count < 1 || $thread_count > $cpu_count)
{
	die($header . "ERROR: Specified thread count (" . $thread_count . ") is invalid.\n       Must be between 1 and " . $cpu_count . " (number of logical CPU cores).\n\n" . $usage . "\n\n");
}

# Status message.
print $header;

# Store contents of search pattern file.
open(my $pattern_fh, "<:encoding(shiftjis)", $pattern_file) or die($!);
my $pattern_line = <$pattern_fh>;
close($pattern_fh);

# Remove extraneous whitespace from pattern text.
$pattern_line =~ s/^\s+|\s+\$//g;
$pattern_line =~ s/\s+/ /g;

# Split the cleaned pattern into individual elements.
my @pattern = split(/ /, $pattern_line);
my $pattern_length = scalar(@pattern);
my $unique_pattern_count = scalar(uniq(@pattern));

# Flag to track whether the pattern line contains only ASCII characters
# (i.e., 0x00-0x7F).
my $is_ascii = 1;

# Iterate over each character in the pattern line.
foreach my $char (split(//, $pattern_line))
{
	# Check the Unicode code point of the character.
	if(ord($char) > 127)
	{
		# If any character exceeds ASCII range, set flag to false.
		$is_ascii = 0;
		
		# No need to continue checking once a non-ASCII character is found.
		last;
	}
}

# Variable to store the final pattern string for display purposes.
my $display_pattern_line;

# The pattern contains non-ASCII characters (e.g., Japanese text).
if(!$is_ascii)
{
	# Hash to map each unique character to a pattern ID (A, B, C, etc).
	my %char_to_id;
	
	# Start the pattern ID sequence at 'A'.
	my $next_id = 'A';
	
	# Array to hold the mapped pattern sequence (e.g., A B C A).
	my @display_pattern;

	# Iterate over each non-whitespace character in the pattern line.
	foreach my $char (grep { $_ !~ /\s/ } split(//, $pattern_line))
	{
		# If this character hasn't been assigned an ID yet, assign the next
		# available letter.
		if(!exists $char_to_id{$char})
		{
			$char_to_id{$char} = $next_id++;
		}
		
		# Add the corresponding pattern ID (A, B, C, etc) to the display
		# sequence.
		push(@display_pattern, $char_to_id{$char});
	}

	# Join the pattern IDs with spaces for a clean display format
	# (e.g., A B C A).
	$display_pattern_line = join(" ", @display_pattern);
}
# For pure ASCII patterns, display the original pattern line directly.
else
{
	$display_pattern_line = $pattern_line;
}

# Calculate how far apart each meaningful byte is in the chunk, considering wildcards.
my $stride = $byte_length + $wildcard;
my $pattern_span = $byte_length + ($pattern_length - 1) * $stride;

# Status message.
print "> Worker threads: " . $thread_count;
print " (default calculated based on number of logical CPU processors minus one)" if(!$custom_thread_count);
print "\n\n";
print "> Character byte length: " . $byte_length . "\n\n";
print "> Wildcard byte count: " . $wildcard . "\n\n";
printf "> %s search pattern: %s\n\n", ($is_ascii ? "Direct" : "Translated"), $display_pattern_line;

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
	if(defined $ignore && $ignore ne "")
	{
		my @extensions = split(/,/, $ignore);

		@files = grep {
			my $f = $_;
			!grep { $f =~ /\.$_\z/i } @extensions
		} @files;
	}
}

# Status message.
print "> Initiating scan process against " . scalar(@files) . " file" . (scalar(@files) == 1 ? "" : "s") . "...\n";

# Initialize counters and start the timer.
my $total_size  :shared = 0;
my $match_count :shared = 0;
my $file_count  :shared = 0;
my $start_time = time();

# Start threading queue.
my $queue = Thread::Queue->new(@files);

# Spawn worker threads. Each will pull files from the queue and process them.
my @threads;

for(1 .. $thread_count)
{
	push @threads, threads->create(\&worker);
}

# Wait for all threads to finish before proceeding.
$_->join() for @threads;

# Calculate total elapsed time.
my $elapsed = time() - $start_time;
my $hours   = int($elapsed / 3600);
my $minutes = int(($elapsed % 3600) / 60);
my $seconds = $elapsed % 60;

# Status message.
print "\n> Scan complete! Found " . $match_count . " match" . ($match_count == 1 ? "" : "es") .
	  " in " . $file_count . " file" . ($file_count == 1 ? "" : "s") . ".\n\n";
printf "> Total scanned size: %d bytes (%.2f MB)\n\n", $total_size, $total_size / (1024 * 1024);
printf "> Time elapsed: %d hour%s, %d minute%s, and %d second%s\n\n",
	   $hours,   ($hours   == 1 ? "" : "s"),
	   $minutes, ($minutes == 1 ? "" : "s"),
	   $seconds, ($seconds == 1 ? "" : "s");

# Thread worker for main program logic.
sub worker
{
	while(defined(my $file = $queue->dequeue_nb))
	{
		# Get the size of the file and skip if too small to match.
		my $size = -s $file;
		next unless defined($size && $size >= $pattern_span);

		# Read file content into memory as raw binary.
		open(my $binary_fh, "<:raw", $file) or next;
		read($binary_fh, my $data, $size);
		close($binary_fh);

		# Add to the total size counter.
		{
			lock($total_size);
			$total_size += $size;
		}

		# Default first match to true.
		my $first_match = 1;

		# Slide across the file byte-by-byte to test for matches.
		for(my $i = 0; $i <= $size - $pattern_span; $i++)
		{
			# Add extra trailing wildcards (if any) to allow full group printing.
			my $display_span = $pattern_span + $wildcard;
			
			# Extract a chunk equal in size to the total pattern span.
			my $chunk = substr($data, $i, $display_span);

			# Compute which offsets in the chunk to actually examine.
			my @positions = map { $_ * $stride } 0 .. $#pattern;
			
			# Extract meaningful byte sequences based on the positions.
			my @groups = map { substr($chunk, $_, $byte_length) } @positions;

			# Quick check to skip if unique count doesn't match.
			next if scalar(uniq(@groups)) != $unique_pattern_count;

			# Perform full match logic using a byte mapping hash, thus ensuring that
			# identical pattern IDs (like 'A' or 'B') map to consistent byte sequences.
			my %byte_map;
			my $valid = 1;

			# Iterate over each element in the pattern.
			for(my $j = 0; $j <= $#pattern; $j ++)
			{
				# The current pattern ID (e.g., 'A', 'B').
				my $id = $pattern[$j];
				
				# The corresponding byte sequence from the data (e.g., 0x14ED).
				my $value = $groups[$j];

				# If this is the first time encountering this pattern ID, store its value.
				if(!exists $byte_map{$id})
				{
					$byte_map{$id} = $value;
				}
				# Otherwise, ensure the value matches the one we've already seen for this ID.
				elsif($byte_map{$id} ne $value)
				{
					# Mismatch found (this chunk is not a valid match).
					$valid = 0;
					
					# Exit the loop since consistency is broken.
					last;
				}
			}

			# Valid match found, display it.
			if($valid)
			{
				# Increase match count by one.
				{
					lock($match_count);
					$match_count++;
				}

				# Print file name only once per file (first match).
				if($first_match)
				{
					# Increase number of files in which matches were found by one.
					{
						lock($file_count);
						$file_count++;
					}

					# Display file name with backslashes on Windows.
					print "\n> " . ($^O =~ /MSWin/ ? ($file =~ s/\//\\/gr) : $file) . "\n";
					
					# Set first match to false.
					$first_match = 0;
				}

				# Status message.
				printf "  - Offset 0x%X (decimal %d)\n", $i, $i;

				# Convert the binary chunk into an array of two-character hex byte strings.
				# Output is formatted by grouping bytes based on the pattern stride, where
				# each group consists of meaningful bytes followed optionally by wildcard
				# bytes.
				my @hex_bytes = unpack("(A2)*", unpack("H*", $chunk));
				my @formatted_groups;

				# Iterate through the hex byte array using the stride value. For each
				# position, extract the meaningful byte group and optionally the trailing
				# wildcards. This ensures proper visual grouping of data sequences for
				# display.
				for(my $i = 0; $i <= $#hex_bytes - $byte_length + 1; $i += $stride)
				{
					# Group the meaningful bytes.
					my $group = join("", @hex_bytes[$i .. $i + $byte_length - 1]);
					push(@formatted_groups, $group);

					# If there are wildcards, print them immediately after the group.
					if($wildcard > 0 && $i + $byte_length <= $#hex_bytes)
					{
						my @wild = @hex_bytes[$i + $byte_length .. ($i + $stride - 1 > $#hex_bytes ? $#hex_bytes : $i + $stride - 1)];
						push(@formatted_groups, join("", @wild)) if(@wild);
					}
				}

				# Print initial indentation before the first group line.
				print "    ";
				
				# Track the number of printed groups to format output into lines of 16 groups
				# each, including both encoded characters and wildcards.
				my $group_count = 0;
				
				# Iterate through each formatted group.
				foreach my $group (@formatted_groups)
				{
					# Print current group.
					print $group . " ";
					
					# Increase group count by one.
					$group_count ++;

					# # If 16 groups have been printed and more remain, insert a newline.
					if($group_count % 16 == 0)
					{
						print "\n";
						
						# Only print indent if more groups remain.
						print "    " if($group_count < scalar(@formatted_groups));
					}
				}

				# Ensure output ends with a newline, unless already ended cleanly.
				print "\n" unless($group_count % 16 == 0);
			}
		}
	}
}