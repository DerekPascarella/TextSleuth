/*
	TextSleuth v2.0
	Written by Derek Pascarella (ateam)

	A brute-force search utility to identify non-standard text encoding formats.
*/

// Include necessary headers.
#include <atomic>
#include <chrono>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <new>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

namespace fs = std::filesystem;

// Set version.
static const std::string version = "2.0";

// Store program usage.
static const std::string usage =
	"Usage: text_sleuth --parameter <value>\n\n"
	"Required:\n"
	"-l, --length NUM         - Encoded character byte length (e.g., 1, 2)\n"
	"-p, --pattern FILE       - Path of pattern file\n"
	"-s, --source DIR or FILE - Path of folder to recursively scan (or single file)\n\n"
	"Optional:\n"
	"-w, --wildcard NUM       - Number of wildcard bytes in between encoded characters (e.g., 1, 2)\n"
	"-i, --ignore STR         - Comma-separated list of file extensions to ignore (e.g., sfd,adx,pvr)\n"
	"-c, --thread-count NUM   - Number of threads to use (default is CPU core count minus one)";

// Store program header.
static const std::string header =
	"\nTextSleuth v" + version + "\n"
	"Written by Derek Pascarella (ateam)\n\n";

// Define the pattern configuration shared by all worker threads.
static long long byte_length;
static long long wildcard;
static long long stride;
static long long pattern_span;
static long long display_span;
static long long pattern_length;
static long long unique_pattern_count;
static std::vector<int> token_group;

// Define the file list and counters shared by all worker threads.
static std::vector<fs::path> files;
static std::atomic<size_t> next_file_index(0);

// Mutex to serialize stdout writes across workers so per-file output stays
// cohesive.
static std::mutex stdout_mutex;

// Per-thread tallies gathered into the shared totals after all workers finish.
struct tally
{
	long long total_size  = 0;
	long long match_count = 0;
	long long file_count  = 0;
};

// Helper to exit with a consistent header/usage/error format.
static void usage_error(const std::string &msg, int exit_code = 255)
{
	std::fprintf(stderr, "%s", (header + "ERROR: " + msg + "\n\n" + usage + "\n\n").c_str());
	std::exit(exit_code);
}

// Join a list of strings with a separator.
static std::string join(const std::vector<std::string> &parts, const std::string &separator)
{
	std::string joined;

	for(size_t i = 0; i < parts.size(); i ++)
	{
		if(i > 0)
		{
			joined += separator;
		}

		joined += parts[i];
	}

	return joined;
}

// Report whether a string is one or more ASCII digits.
static bool is_whole_number(const std::string &text)
{
	if(text.empty())
	{
		return false;
	}

	for(char c : text)
	{
		if(c < '0' || c > '9')
		{
			return false;
		}
	}

	return true;
}

// Parse a digit string, saturating at a value far larger than any real file.
static long long parse_whole_number(const std::string &text)
{
	long long value = 0;

	for(char c : text)
	{
		if(value > 1000000000000000LL)
		{
			return 1000000000000000LL;
		}

		value = value * 10 + (c - '0');
	}

	return value;
}

// Return the byte count of the Shift-JIS character starting at the given
// position (1 or 2).
static size_t sjis_char_length(const std::string &text, size_t pos)
{
	unsigned char lead = static_cast<unsigned char>(text[pos]);

	if(((lead >= 0x81 && lead <= 0x9F) || (lead >= 0xE0 && lead <= 0xFC)) && pos + 1 < text.size())
	{
		return 2;
	}

	return 1;
}

// Report whether a Shift-JIS character is whitespace (ASCII whitespace or the
// full-width space 0x8140).
static bool sjis_char_is_whitespace(const std::string &character)
{
	if(character.size() == 1)
	{
		char c = character[0];
		return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
	}

	return static_cast<unsigned char>(character[0]) == 0x81 && static_cast<unsigned char>(character[1]) == 0x40;
}

// Advance a pattern ID in the style of Perl's string increment (e.g., "Z"
// becomes "AA").
static std::string increment_id(std::string id)
{
	for(size_t i = id.size(); i > 0; i --)
	{
		if(id[i - 1] != 'Z')
		{
			id[i - 1] ++;
			return id;
		}

		id[i - 1] = 'A';
	}

	return "A" + id;
}

// Lowercase a string for case-insensitive comparison.
static std::string lowercase(std::string text)
{
	for(char &c : text)
	{
		c = std::tolower(static_cast<unsigned char>(c));
	}

	return text;
}

// Return the file path formatted for display, with backslashes on Windows.
static std::string display_path(const fs::path &file)
{
	std::string text = file.string();

	if(fs::path::preferred_separator == '\\')
	{
		for(char &c : text)
		{
			if(c == '/')
			{
				c = '\\';
			}
		}
	}

	return text;
}

// Per-file worker. Reads the file, scans it for pattern matches, prints any
// matches under the stdout mutex as a single cohesive block, and adds its
// tallies (bytes scanned, match count, did-match flag) to the thread's totals.
static void scan_file(const fs::path &file, tally &totals)
{
	// Get the size of the file and skip if too small to match.
	std::error_code ec;
	unsigned long long size = fs::file_size(file, ec);

	if(ec || static_cast<long long>(size) < pattern_span)
	{
		return;
	}

	// Skip if the file cannot fit in memory.
	if(size > SIZE_MAX - 16)
	{
		return;
	}

	// Read file content into memory as raw binary. Opening via the path
	// object keeps wide-character file names working on Windows.
	std::ifstream binary_fh(file, std::ios::binary);

	if(!binary_fh)
	{
		return;
	}

	std::vector<unsigned char> data;

	try
	{
		data.resize(size);
	}
	catch(const std::bad_alloc &)
	{
		return;
	}

	binary_fh.read(reinterpret_cast<char *>(data.data()), data.size());
	long long data_size = binary_fh.gcount();
	binary_fh.close();

	// Buffer all matches for this file so they can be flushed under the stdout
	// mutex as one cohesive block.
	struct match
	{
		long long offset;
		long long chunk_size;
	};

	std::vector<match> local_matches;
	std::vector<const unsigned char *> groups(unique_pattern_count);

	// A pattern with no elements scans nothing.
	long long last_offset = pattern_length > 0 ? data_size - pattern_span : -1;

	// Slide across the file byte-by-byte to test for matches. Identical pattern
	// IDs must map to identical byte groups, and distinct pattern IDs must map
	// to distinct byte groups.
	for(long long i = 0; i <= last_offset; i ++)
	{
		const unsigned char *base = data.data() + i;
		int assigned = 0;
		bool valid = true;

		for(long long j = 0; j < pattern_length; j ++)
		{
			const unsigned char *group = base + j * stride;
			int id = token_group[j];

			// A previously seen pattern ID must repeat its byte group exactly.
			if(id < assigned)
			{
				if(std::memcmp(group, groups[id], byte_length) != 0)
				{
					valid = false;
					break;
				}
			}
			// A new pattern ID must differ from every byte group seen so far.
			else
			{
				for(int k = 0; k < assigned; k ++)
				{
					if(std::memcmp(group, groups[k], byte_length) == 0)
					{
						valid = false;
						break;
					}
				}

				if(!valid)
				{
					break;
				}

				groups[assigned] = group;
				assigned ++;
			}
		}

		if(!valid)
		{
			continue;
		}

		// Record the match for later display under the stdout mutex. Trailing
		// wildcards (if any) are included in the display chunk, truncated at
		// end of file.
		long long chunk_size = display_span;

		if(chunk_size > data_size - i)
		{
			chunk_size = data_size - i;
		}

		local_matches.push_back({i, chunk_size});
	}

	// Per-file tallies.
	long long local_match_count = local_matches.size();
	long long had_match         = local_match_count > 0 ? 1 : 0;

	// Flush this file's matches as a single mutex-locked block, so the file
	// header and its match list never interleave with another worker's output.
	if(had_match)
	{
		std::lock_guard<std::mutex> lock(stdout_mutex);

		// Display file name with backslashes on Windows.
		std::printf("\n> %s\n", display_path(file).c_str());

		for(const match &m : local_matches)
		{
			// Status message.
			std::printf("  - Offset 0x%llX (decimal %lld)\n",
				static_cast<unsigned long long>(m.offset), m.offset);

			// Convert the binary chunk into hex byte strings grouped by the
			// pattern stride, where each group consists of meaningful bytes
			// followed optionally by wildcard bytes.
			const unsigned char *chunk = data.data() + m.offset;
			long long chunk_bytes = m.chunk_size;
			std::vector<std::string> formatted_groups;

			for(long long j = 0; j <= chunk_bytes - byte_length; j += stride)
			{
				// Group the meaningful bytes.
				std::string group;

				for(long long b = j; b < j + byte_length; b ++)
				{
					char hex[3];
					std::snprintf(hex, sizeof(hex), "%02x", chunk[b]);
					group += hex;
				}

				formatted_groups.push_back(group);

				// If there are wildcards, print them immediately after the group.
				if(wildcard > 0 && j + byte_length <= chunk_bytes - 1)
				{
					long long wild_end = j + stride - 1;

					if(wild_end > chunk_bytes - 1)
					{
						wild_end = chunk_bytes - 1;
					}

					std::string wild;

					for(long long b = j + byte_length; b <= wild_end; b ++)
					{
						char hex[3];
						std::snprintf(hex, sizeof(hex), "%02x", chunk[b]);
						wild += hex;
					}

					if(!wild.empty())
					{
						formatted_groups.push_back(wild);
					}
				}
			}

			// Print initial indentation before the first group line.
			std::printf("    ");

			// Track the number of printed groups to format output into lines of
			// 16 groups each, including both encoded characters and wildcards.
			size_t group_count = 0;

			// Iterate through each formatted group.
			for(const std::string &group : formatted_groups)
			{
				// Print current group.
				std::printf("%s ", group.c_str());

				// Increase group count by one.
				group_count ++;

				// If 16 groups have been printed and more remain, insert a newline.
				if(group_count % 16 == 0)
				{
					std::printf("\n");

					// Only print indent if more groups remain.
					if(group_count < formatted_groups.size())
					{
						std::printf("    ");
					}
				}
			}

			// Ensure output ends with a newline, unless already ended cleanly.
			if(group_count % 16 != 0)
			{
				std::printf("\n");
			}
		}

		std::fflush(stdout);
	}

	// Add this file's tallies to the thread's totals.
	totals.total_size  += size;
	totals.match_count += local_match_count;
	totals.file_count  += had_match;
}

// Thread worker for main program logic. Each worker pulls the next unscanned
// file by atomic index until the list is exhausted.
static void worker(tally &totals)
{
	while(true)
	{
		size_t index = next_file_index.fetch_add(1);

		if(index >= files.size())
		{
			break;
		}

		scan_file(files[index], totals);
	}
}

int main(int argc, char *argv[])
{
	// Retrieve CPU count.
	long long cpu_count = std::thread::hardware_concurrency();

	if(cpu_count < 1)
	{
		cpu_count = 1;
	}

	// Define input parameters.
	std::string byte_length_arg, pattern_file, search_path, wildcard_arg, ignore, thread_count_arg;
	bool have_length = false, have_pattern = false, have_source = false;
	bool have_wildcard = false, have_ignore = false, have_thread_count = false;

	// No options were specified.
	if(argc < 2)
	{
		usage_error("No options specified.");
	}

	// Table mapping each option's short and long names to its storage.
	struct option_entry
	{
		const char *short_name;
		const char *long_name;
		std::string *target;
		bool *have_flag;
	};

	const option_entry option_table[] =
	{
		{"l", "length",       &byte_length_arg,  &have_length},
		{"p", "pattern",      &pattern_file,     &have_pattern},
		{"s", "source",       &search_path,      &have_source},
		{"w", "wildcard",     &wildcard_arg,     &have_wildcard},
		{"i", "ignore",       &ignore,           &have_ignore},
		{"c", "thread-count", &thread_count_arg, &have_thread_count},
	};

	// Parse our parameters and arguments, collecting leftover invalid
	// parameters.
	std::vector<std::string> args(argv + 1, argv + argc);
	std::vector<std::string> unknown_options;

	for(size_t i = 0; i < args.size(); i ++)
	{
		const std::string &arg = args[i];

		// A bare "--" ends option parsing.
		if(arg == "--")
		{
			for(size_t j = i + 1; j < args.size(); j ++)
			{
				if(args[j].rfind("--", 0) == 0)
				{
					unknown_options.push_back(args[j]);
				}
			}

			break;
		}

		// Non-option tokens are ignored.
		if(arg.size() < 2 || arg[0] != '-')
		{
			continue;
		}

		// Accept both single-dash and double-dash forms, with the value
		// attached by "=" or supplied as the next argument.
		size_t name_start = (arg[1] == '-') ? 2 : 1;
		std::string name = arg.substr(name_start);
		std::string value;
		bool has_value = false;
		size_t equals_pos = name.find('=');

		if(equals_pos != std::string::npos)
		{
			value = name.substr(equals_pos + 1);
			name = name.substr(0, equals_pos);
			has_value = true;
		}

		const option_entry *entry = nullptr;

		for(const option_entry &candidate : option_table)
		{
			if(name == candidate.short_name || name == candidate.long_name)
			{
				entry = &candidate;
				break;
			}
		}

		// Unknown double-dash options are collected and reported.
		if(entry == nullptr)
		{
			if(arg.rfind("--", 0) == 0)
			{
				unknown_options.push_back(arg);
			}

			continue;
		}

		if(!has_value)
		{
			// An option with no remaining value argument is treated as unset.
			if(i + 1 >= args.size())
			{
				continue;
			}

			value = args[++ i];
		}

		*entry->target = value;
		*entry->have_flag = true;
	}

	// Identify leftover invalid parameters.
	if(!unknown_options.empty())
	{
		usage_error("One or more invalid options specified (" + join(unknown_options, ", ") + ").");
	}

	// Default wildcard count to zero.
	if(!have_wildcard)
	{
		wildcard_arg = "0";
	}

	// Set default thread count if none specified.
	int custom_thread_count = 1;

	if(!have_thread_count)
	{
		thread_count_arg = std::to_string(cpu_count > 1 ? cpu_count - 1 : 1);

		custom_thread_count = 0;
	}

	// Perform input validation. Identify any missing required parameters and
	// report them together.
	std::vector<std::string> missing;

	if(!have_length || byte_length_arg.empty())
	{
		missing.push_back("--length");
	}

	if(!have_pattern || pattern_file.empty())
	{
		missing.push_back("--pattern");
	}

	if(!have_source || search_path.empty())
	{
		missing.push_back("--source");
	}

	if(!missing.empty())
	{
		usage_error("Missing required parameter" + std::string(missing.size() == 1 ? "" : "s") +
			": " + join(missing, ", ") + ".");
	}

	// Validate character byte length (must be a positive integer).
	if(!is_whole_number(byte_length_arg) || parse_whole_number(byte_length_arg) < 1)
	{
		usage_error("Specified character byte length is invalid, must be whole number greater than zero.");
	}

	// Validate wildcard count (must be a non-negative integer).
	if(!is_whole_number(wildcard_arg))
	{
		usage_error("Specified wildcard count is invalid, must be whole number zero or greater.");
	}

	byte_length = parse_whole_number(byte_length_arg);
	wildcard    = parse_whole_number(wildcard_arg);

	// Validate pattern file. Check folder-vs-file before readability so that
	// the error message is specific when the user points --pattern at a
	// directory. A missing file exits with ENOENT and an unreadable one with
	// EACCES, mirroring Perl's errno propagation through die.
	std::error_code ec;

	if(fs::is_directory(pattern_file, ec))
	{
		usage_error("Specified pattern file is a folder, cannot read.");
	}
	else if(!fs::exists(pattern_file, ec))
	{
		usage_error("Specified pattern file does not exist.", ENOENT);
	}
	else if(access(pattern_file.c_str(), R_OK) != 0)
	{
		usage_error("Cannot read specified pattern file.", EACCES);
	}

	// Validate search path.
	if(!fs::exists(search_path, ec))
	{
		usage_error("Specified search path does not exist.", ENOENT);
	}
	else if(access(search_path.c_str(), R_OK) != 0)
	{
		usage_error("Cannot read specified search path.", EACCES);
	}

	// Validate thread count.
	long long thread_count = is_whole_number(thread_count_arg) ? parse_whole_number(thread_count_arg) : 0;

	if(!is_whole_number(thread_count_arg) || thread_count < 1 || thread_count > cpu_count)
	{
		usage_error("Specified thread count (" + thread_count_arg + ") is invalid.\n       Must be between 1 and " +
			std::to_string(cpu_count) + " (number of logical CPU cores).");
	}

	// Status message.
	std::printf("%s", header.c_str());

	// Store the first line of the search pattern file.
	std::FILE *pattern_fh = std::fopen(pattern_file.c_str(), "rb");

	if(pattern_fh == nullptr)
	{
		std::fprintf(stderr, "%s\n", std::strerror(errno));
		return errno;
	}

	std::string pattern_line;
	int c;

	while((c = std::fgetc(pattern_fh)) != EOF && c != '\n')
	{
		pattern_line += static_cast<char>(c);
	}

	std::fclose(pattern_fh);

	// Split the pattern into individual elements, treating any run of
	// whitespace (including full-width Shift-JIS spaces) as one separator.
	std::vector<std::string> pattern;
	std::string current_token;

	for(size_t i = 0; i < pattern_line.size();)
	{
		size_t char_size = sjis_char_length(pattern_line, i);
		std::string character = pattern_line.substr(i, char_size);

		if(sjis_char_is_whitespace(character))
		{
			if(!current_token.empty())
			{
				pattern.push_back(current_token);
				current_token.clear();
			}
		}
		else
		{
			current_token += character;
		}

		i += char_size;
	}

	if(!current_token.empty())
	{
		pattern.push_back(current_token);
	}

	pattern_length = pattern.size();

	// Map each pattern element to a group number in first-occurrence order.
	// Identical elements share a group, and the group count is the number of
	// unique elements.
	std::map<std::string, int> id_to_group;

	for(const std::string &id : pattern)
	{
		auto found = id_to_group.find(id);

		if(found == id_to_group.end())
		{
			int group = id_to_group.size();
			id_to_group[id] = group;
			token_group.push_back(group);
		}
		else
		{
			token_group.push_back(found->second);
		}
	}

	unique_pattern_count = id_to_group.size();

	// Flag to track whether the pattern contains only ASCII characters
	// (i.e., 0x00-0x7F).
	bool is_ascii = true;

	for(const std::string &id : pattern)
	{
		for(char ch : id)
		{
			if(static_cast<unsigned char>(ch) > 127)
			{
				is_ascii = false;
				break;
			}
		}

		if(!is_ascii)
		{
			break;
		}
	}

	// Variable to store the final pattern string for display purposes.
	std::string display_pattern_line;

	// The pattern contains non-ASCII characters (e.g., Japanese text). Map each
	// unique character to a pattern ID (A, B, C, etc).
	if(!is_ascii)
	{
		std::map<std::string, std::string> char_to_id;
		std::string next_id = "A";
		std::vector<std::string> display_pattern;

		for(const std::string &id : pattern)
		{
			for(size_t i = 0; i < id.size();)
			{
				size_t char_size = sjis_char_length(id, i);
				std::string character = id.substr(i, char_size);

				if(char_to_id.find(character) == char_to_id.end())
				{
					char_to_id[character] = next_id;
					next_id = increment_id(next_id);
				}

				display_pattern.push_back(char_to_id[character]);

				i += char_size;
			}
		}

		display_pattern_line = join(display_pattern, " ");
	}
	// For pure ASCII patterns, display the original pattern elements directly.
	else
	{
		display_pattern_line = join(pattern, " ");
	}

	// Calculate how far apart each meaningful byte is in the chunk, considering
	// wildcards.
	stride       = byte_length + wildcard;
	pattern_span = byte_length + (pattern_length - 1) * stride;
	display_span = pattern_span + wildcard;

	// Status message.
	std::printf("> Worker threads: %lld", thread_count);

	if(!custom_thread_count)
	{
		std::printf(" (default calculated based on number of logical CPU processors minus one)");
	}

	std::printf("\n\n");
	std::printf("> Character byte length: %lld\n\n", byte_length);
	std::printf("> Wildcard byte count: %lld\n\n", wildcard);
	std::printf("> %s search pattern: %s\n\n", is_ascii ? "Direct" : "Translated", display_pattern_line.c_str());

	// If the path is a single file, add it to the list directly.
	if(fs::is_regular_file(search_path, ec))
	{
		files.push_back(search_path);
	}
	// Otherwise, recursively find all files in the specified directory.
	else
	{
		fs::recursive_directory_iterator it(search_path, fs::directory_options::skip_permission_denied, ec);
		fs::recursive_directory_iterator end;

		while(!ec && it != end)
		{
			std::error_code entry_ec;

			if(it->is_regular_file(entry_ec))
			{
				files.push_back(it->path());
			}

			it.increment(ec);
		}

		// Apply optional file extension filtering.
		if(have_ignore && !ignore.empty())
		{
			std::vector<std::string> extensions;
			std::string current_extension;

			for(char ch : ignore)
			{
				if(ch == ',')
				{
					extensions.push_back(current_extension);
					current_extension.clear();
				}
				else
				{
					current_extension += ch;
				}
			}

			extensions.push_back(current_extension);

			for(std::string &extension : extensions)
			{
				extension = lowercase(extension);
			}

			std::vector<fs::path> kept;

			// Match each extension as a case-insensitive suffix preceded by
			// a dot.
			for(const fs::path &file : files)
			{
				std::string name = lowercase(file.filename().string());
				bool ignored = false;

				for(const std::string &extension : extensions)
				{
					if(name.size() > extension.size() &&
					   name[name.size() - extension.size() - 1] == '.' &&
					   name.compare(name.size() - extension.size(), extension.size(), extension) == 0)
					{
						ignored = true;
						break;
					}
				}

				if(!ignored)
				{
					kept.push_back(file);
				}
			}

			files = kept;
		}
	}

	// Status message.
	std::printf("> Initiating scan process against %lld file%s...\n",
		static_cast<long long>(files.size()), files.size() == 1 ? "" : "s");
	std::fflush(stdout);

	// Start the timer.
	auto start_time = std::chrono::steady_clock::now();

	// Spawn worker threads. Each will pull files by atomic index and process
	// them.
	std::vector<tally> tallies(thread_count);
	std::vector<std::thread> threads;

	for(long long i = 0; i < thread_count; i ++)
	{
		threads.emplace_back(worker, std::ref(tallies[i]));
	}

	// Wait for all threads to finish before proceeding.
	for(std::thread &t : threads)
	{
		t.join();
	}

	// Gather the per-thread tallies into the final totals.
	long long total_size  = 0;
	long long match_count = 0;
	long long file_count  = 0;

	for(const tally &t : tallies)
	{
		total_size  += t.total_size;
		match_count += t.match_count;
		file_count  += t.file_count;
	}

	// Calculate total elapsed time.
	long long elapsed = static_cast<long long>(
		std::chrono::duration<double>(std::chrono::steady_clock::now() - start_time).count());
	long long hours   = elapsed / 3600;
	long long minutes = (elapsed % 3600) / 60;
	long long seconds = elapsed % 60;

	// Status message.
	std::printf("\n> Scan complete! Found %lld match%s in %lld file%s.\n\n",
		match_count, match_count == 1 ? "" : "es",
		file_count, file_count == 1 ? "" : "s");
	std::printf("> Total scanned size: %lld bytes (%.2f MB)\n\n",
		total_size, static_cast<double>(total_size) / (1024 * 1024));
	std::printf("> Time elapsed: %lld hour%s, %lld minute%s, and %lld second%s\n\n",
		hours,   hours   == 1 ? "" : "s",
		minutes, minutes == 1 ? "" : "s",
		seconds, seconds == 1 ? "" : "s");

	return 0;
}