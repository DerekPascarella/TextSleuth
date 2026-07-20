#!/usr/bin/perl
#
# TextSleuth v1.2
# Written by Derek Pascarella (ateam)
#
# A brute-force search utility to identify non-standard text encoding formats.

# Include necessary modules.
use strict;
use MCE::Util;
use MCE::Loop;
use File::Find;
use MCE::Mutex;
use MCE::Mutex::Channel;
use Time::HiRes     ("time");
use List::MoreUtils ("uniq");
use Getopt::Long    (":config", "no_ignore_case", "no_auto_abbrev");

# Supress default error messages.
Getopt::Long::Configure("pass_through");

# Retrieve CPU count.
my $cpu_count = MCE::Util::get_ncpu();

# Set version.
my $version = "1.2";

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

# Helper to die with a consistent header/usage/error format.
sub usage_error
{
	my $msg = shift;
	die($header . "ERROR: " . $msg . "\n\n" . $usage . "\n\n");
}

# No options were specified.
if(scalar(@ARGV) == 0)
{
	die($header . "ERROR: No options specified.\n\n" . $usage . "\n\n");
}

# Define our parameters and arguments.
GetOptions(
	"l|length=s"       => \$byte_length,
	"p|pattern=s"      => \$pattern_file,
	"s|source=s"       => \$search_path,
	"w|wildcard=s"     => \$wildcard,
	"i|ignore=s"       => \$ignore,
	"c|thread-count=s" => \$thread_count
);

# Identify leftover invalid parameters.
my @unknown_options = grep { /^--/ } @ARGV;

if(@unknown_options)
{
	usage_error("One or more invalid options specified (" . join(", ", @unknown_options) . ").");
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

# Perform input validation. Each required parameter is checked individually so
# that a missing one produces a precise error message. Identify any missing
# required parameters and report them together.
my @missing;
push(@missing, "--length")  if(!defined $byte_length  || $byte_length  eq "");
push(@missing, "--pattern") if(!defined $pattern_file || $pattern_file eq "");
push(@missing, "--source")  if(!defined $search_path  || $search_path  eq "");

if(@missing)
{
	usage_error("Missing required parameter" . (@missing == 1 ? "" : "s") . ": " . join(", ", @missing) . ".");
}

# Validate character byte length (must be a positive integer).
if($byte_length !~ /^\d+$/ || $byte_length < 1)
{
	usage_error("Specified character byte length is invalid, must be whole number greater than zero.");
}

# Validate wildcard count (must be a non-negative integer).
if($wildcard !~ /^\d+$/)
{
	usage_error("Specified wildcard count is invalid, must be whole number zero or greater.");
}

# Validate pattern file. Check folder-vs-file before readability so that the
# error message is specific when the user points --pattern at a directory.
if(-d $pattern_file)
{
	usage_error("Specified pattern file is a folder, cannot read.");
}
elsif(!-e $pattern_file)
{
	usage_error("Specified pattern file does not exist.");
}
elsif(!-r $pattern_file)
{
	usage_error("Cannot read specified pattern file.");
}

# Validate search path.
if(!-e $search_path)
{
	usage_error("Specified search path does not exist.");
}
elsif(!-r $search_path)
{
	usage_error("Cannot read specified search path.");
}

# Validate thread count.
if($thread_count !~ /^\d+$/ || $thread_count < 1 || $thread_count > $cpu_count)
{
	usage_error("Specified thread count (" . $thread_count . ") is invalid.\n       Must be between 1 and " . $cpu_count . " (number of logical CPU cores).");
}

# Status message.
print $header;

# Store contents of search pattern file.
open(my $pattern_fh, "<:encoding(shiftjis)", $pattern_file) or die($!);
my $pattern_line = <$pattern_fh>;
close($pattern_fh);

# Remove extraneous whitespace from pattern text.
$pattern_line =~ s/^\s+|\s+$//g;
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
	my $next_id = "A";

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

# Build a compiled regex that encodes the pattern's structural constraints.
# Each unique pattern ID becomes a capturing group of $byte_length bytes. Every
# subsequent occurrence of that ID becomes a numbered backreference (\g{N}).
# Wildcards are emitted as inline ".{$wildcard}" separators.
my %id_to_group;
my $next_group = 1;
my @rx_parts;

foreach my $id (@pattern)
{
	if(exists $id_to_group{$id})
	{
		# Subsequent occurrence: emit a backreference to the original group.
		push(@rx_parts, "\\g{" . $id_to_group{$id} . "}");
	}
	else
	{
		# First occurrence: assign the next capture group number.
		$id_to_group{$id} = $next_group ++;
		push(@rx_parts, "(.{" . $byte_length . "})");
	}
}

# Wildcard bytes between elements (or empty string if none).
my $rx_separator = $wildcard > 0 ? ".{" . $wildcard . "}" : "";

# Final compiled regex. The /s flag lets "." match any byte including newline.
my $rx_string = join($rx_separator, @rx_parts);
my $pattern_regex = qr/$rx_string/s;

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
my $total_size  = 0;
my $match_count = 0;
my $file_count  = 0;
my $start_time  = time();

# Mutex to serialize STDOUT writes across workers so per-file output stays
# cohesive.
my $stdout_mutex = MCE::Mutex->new;

# Configure the MCE worker pool. Each worker processes one file per invocation
# (chunk_size of 1).
MCE::Loop->init(
	max_workers => $thread_count,
	chunk_size  => 1,
	gather      => sub
	{
		my $r = shift;
		$total_size  += $r->[0];
		$match_count += $r->[1];
		$file_count  += $r->[2];
	},
);

# Dispatch the worker over every file.
mce_loop
{
	my ($mce, $chunk_ref) = @_;
	worker($chunk_ref->[0]);
} @files;

# Shut down the worker pool.
MCE::Loop->finish;

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

# Per-file worker. Reads the file, scans it for pattern matches, prints any
# matches under the STDOUT mutex as a single cohesive block, and reports its
# tallies (bytes scanned, match count, did-match flag) back to the parent
# process via MCE->gather.
sub worker
{
	my $file = shift;

	# Get the size of the file and skip if too small to match.
	my $size = -s $file;
	return unless defined($size) && $size >= $pattern_span;

	# Read file content into memory as raw binary.
	open(my $binary_fh, "<:raw", $file) or return;
	read($binary_fh, my $data, $size);
	close($binary_fh);

	# Trailing wildcards (if any) are included in the display chunk so the
	# rendered hex output shows the wildcards after the final meaningful byte.
	my $display_span = $pattern_span + $wildcard;

	# Buffer all matches for this file so they can be flushed under the STDOUT
	# mutex as one cohesive block.
	my @local_matches;

	# Reset the scan position before iterating over matches in this file.
	pos($data) = 0;

	# Scan the file for every position where the structural pattern (the
	# equality constraints between pattern IDs) holds. The regex engine
	# performs the sliding window in C, so we only revisit positions that
	# already passed the structural test.
	while($data =~ /$pattern_regex/g)
	{
		# Offset in the file where the current match starts.
		my $i = $-[0];

		# Force the next regex attempt to start one byte after this match's
		# start. This preserves the original byte-by-byte semantics so that
		# overlapping matches at adjacent offsets aren't skipped.
		pos($data) = $i + 1;

		# Read the captured byte sequences (one per unique pattern ID).
		my @captures = map { substr($data, $-[$_], $+[$_] - $-[$_]) } 1 .. $unique_pattern_count;

		# The regex's backreferences already enforced every equality
		# constraint between pattern IDs. The remaining constraint is that
		# distinct pattern IDs must map to distinct byte sequences.
		my %seen;
		my $valid = 1;

		foreach my $cap (@captures)
		{
			if($seen{$cap} ++)
			{
				$valid = 0;
				last;
			}
		}

		next unless $valid;

		# Record the match for later display under the STDOUT mutex.
		push(@local_matches, [$i, substr($data, $i, $display_span)]);
	}

	# Per-file tallies.
	my $local_match_count = scalar(@local_matches);
	my $had_match         = $local_match_count > 0 ? 1 : 0;

	# Flush this file's matches as a single mutex-locked block, so the file
	# header and its match list never interleave with another worker's output.
	if($had_match)
	{
		$stdout_mutex->synchronize(sub
		{
			# Display file name with backslashes on Windows.
			print "\n> " . ($^O =~ /MSWin/ ? ($file =~ s/\//\\/gr) : $file) . "\n";

			foreach my $match (@local_matches)
			{
				my ($i, $chunk) = @$match;

				# Status message.
				printf "  - Offset 0x%X (decimal %d)\n", $i, $i;

				# Convert the binary chunk into an array of two-character hex byte strings.
				# Output is formatted by grouping bytes based on the pattern stride, where
				# each group consists of meaningful bytes followed optionally by wildcard
				# bytes.
				my @hex_bytes = unpack("(H2)*", $chunk);
				my @formatted_groups;

				# Iterate through the hex byte array using the stride value. For each
				# position, extract the meaningful byte group and optionally the trailing
				# wildcards. This ensures proper visual grouping of data sequences for
				# display.
				for(my $j = 0; $j <= $#hex_bytes - $byte_length + 1; $j += $stride)
				{
					# Group the meaningful bytes.
					my $group = join("", @hex_bytes[$j .. $j + $byte_length - 1]);
					push(@formatted_groups, $group);

					# If there are wildcards, print them immediately after the group.
					if($wildcard > 0 && $j + $byte_length <= $#hex_bytes)
					{
						my @wild = @hex_bytes[$j + $byte_length .. ($j + $stride - 1 > $#hex_bytes ? $#hex_bytes : $j + $stride - 1)];
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

					# If 16 groups have been printed and more remain, insert a newline.
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
		});
	}

	# Report this file's tallies back to the parent. The gather callback (set
	# in MCE::Loop->init) accumulates these into the shared counters.
	MCE->gather([$size, $local_match_count, $had_match]);
}