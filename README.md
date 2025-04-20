# TextSleuth
TextSleuth is a brute-force search utility to identify non-standard text encoding formats.

It supports multi-threading for enhanced performance, as well as a host of flexible options. It performs its scan by sliding a window over binary data and checking for repeating byte patterns based on user-defined encoding rules. It calculates byte strides between elements (accounting for wildcards), maps pattern IDs to actual byte sequences, and validates structural consistency. The algorithm is optimized by:

- Precomputing offsets and pattern span.
- Skipping chunks early if unique group counts don’t match.
- Using multithreading with a shared queue for parallel file processing.
- Minimizing disk I/O by reading entire files into memory once.

TextSleuth's primary target users are hackers and reverse-engineers developing video game translation patches, especially those considered "retro" where custom text encoding formats were often used (rather than standards like ASCII or Shift-JIS).

## Current Version
TextSleuth is currently at version [1.0](https://github.com/DerekPascarella/TextSleuth/releases/download/1.0/TextSleuth.v1.0.zip).

## Changelog
- **Version 1.0 (2025-04-19)**
    - Initial release.

## Benchmarks
With support for multi-threading, TextSleuth can be scaled as desired. By default, it will consume one fewer thread than the total logical processor count of the host computer on which it's executed.

On an AMD Ryzen 5 4600H running at 3.0 GHz with six cores and 12 logical processors (threads), where TextSleuth is consuming 11 threads, approximately 20 MB of data can be searched per minute.

## Usage
TextSleuth is a command-line utility to be invoked as follows.

Long option format:
```
text_sleuth --parameter <value>
```

Short option format:
```
text_sleuth -p <value>
```

Below are a list of all available options, both required and optional.
```
Required:
-l, --length NUM         - Encoded character byte length (e.g., 1, 2)
-p, --pattern FILE       - Path of pattern file
-s, --source DIR or FILE - Path of folder to recursively scan (or single file)

Optional:
-w, --wildcard NUM       - Number of wildcard bytes in between encoded characters (e.g., 1, 2)
-i, --ignore STR         - Comma-separated list of file extensions to ignore (e.g., sfd,adx,pvr)
-c, --thread-count NUM   - Number of threads to use (default is CPU core count minus one)
```

## Example Scenario
Consider the following example for the FM Towns game "Phobos".

After some analysis of the game data, it was discovered that in-game dialogue text was not compressed, but definitely stored using a non-standard text encoding format.

To uncover the custom character encoding format leveraged by the game, the user finds a chunk of text containing a sufficient number of repeating characters. Since TextSleuth will perform a brute-force search, the user wants to eliminate as many false-positives as possible by identifying sequences of characters that are likely to be unique.

Below is one such example, where `たアンドロイド『アーマロイド』を` contains 16 characters, five of which are not unique (i.e., they are repeated).

![Screenshot](https://github.com/DerekPascarella/TextSleuth/blob/main/images/in-game_screenshot.png?raw=true)

After identifying such a text chunk, the user must transcribe a pattern using any ASCII characters of their choice. For example, one can assign a given Japanese character to the letter `A`, or to the number `1`.

Below is an example of translating the string of text into a valid pattern.

![Screenshot](https://github.com/DerekPascarella/TextSleuth/blob/main/images/text_pattern.png?raw=true)

Once the pattern has been identified, it's then to be written to a text file.

![Screenshot](https://github.com/DerekPascarella/TextSleuth/blob/main/images/notepad.png?raw=true)

With this pattern saved as `phobos.txt`, and the extracted game data stored in a folder named `inp`, it's time to construct the first search command.

For the initial attempt, the user assumes a two-byte format with no wildcards in between.

`text_sleuth.exe --length 2 --pattern phobos.txt --source inp\`

![Screenshot](https://github.com/DerekPascarella/TextSleuth/blob/main/images/terminal.png?raw=true)

As seen above, a match was found on the first attempt, and in a total of five seconds! TextSleuth is reporting that an array of bytes matching the defined search criteria pattern was found at offset `0x892` inside the file `SNRP`.

Consider the matched byte array. It appears to be potentially valid, as a discernible format begins to take shape for a proposed custom text encoding format.

```
14ed 1c0a 1c9c 1c43 1c6c 1c1a 1c43 0cbb 1c0a 0cda 1ceb 1c6c 1c1a 1c43 0cc3 1487
```

As an initial test, the user will repeat the first two-byte sequence (`0x14 0xed`) a total of ten times to see if the change is reflected in the game itself.

As seen below, the first character in the text chunk, `た`, is indeed repeated ten times!

![Screenshot](https://github.com/DerekPascarella/TextSleuth/blob/main/images/change_test.png?raw=true)

It's at this point that the user undergoes the process of mapping out the table of all characters supported by the game, after which text extraction and additional hacking efforts can take place.

Note that should the initial scan failed to produce meaningful results, the user would attempt again with different options, such as a byte-length of one (instead of two). Additionally, wildcard options may be used.

For example, one could imagine a scenario where the matched data from this example used `0x00` terminator bytes in between encoded characters, as shown below.

```
14 ed 00 1c 0a 00 1c 9c 00 1c 43 00 1c 6c 00 1c
1a 00 1c 43 00 0c bb 00 1c 0a 00 0c da 00 1c eb
00 1c 6c 00 1c 1a 00 1c 43 00 0c c3 00 14 87 00
```

TextSleuth would fail to identify this byte array as a match unless the `--wildcard` option was used. See example command below.

`text_sleuth.exe --length 2 --pattern phobos.txt --source inp\ --wildcard 1`

Another example could include two wildcard bytes, where `00 01` ends character one, `00 02` ends characters two, and so on.

```
14 ed 00 01 1c 0a 00 02 1c 9c 00 03 1c 43 00 04
1c 6c 00 05 1c 1a 00 06 1c 43 00 07 0c bb 00 08
1c 0a 00 09 0c da 00 0a 1c eb 00 0b 1c 6c 00 0c
1c 1a 00 0d 1c 43 00 0e 0c c3 00 0f 14 87 00 10
```

In such a case, the following command could be used to successfully match it.

`text_sleuth.exe --length 2 --pattern phobos.txt --source inp\ --wildcard 2`
