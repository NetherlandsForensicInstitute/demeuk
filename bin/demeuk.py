#!/usr/bin/env python3
r"""
.. code-block:: none

    Demeuk - a simple tool to clean up corpora

    Usage:
        demeuk [options]

    Examples:
        demeuk -i inputfile.tmp -o outputfile.dict -l logfile.txt
        demeuk -i "inputfile*.txt" -o outputfile.dict -l logfile.txt
        demeuk -i "inputdir/*" -o outputfile.dict -l logfile.txt
        demeuk -i inputfile -o outputfile -j 24
        demeuk -i inputfile -o outputfile -c -e
        demeuk -i inputfile -o outputfile --threads all
        cat inputfile | demeuk --leak -j all | sort -u > outputfile

    Standard Options:
        -i --input <path to file>       Specify the input file to be cleaned, or provide a glob pattern.
                                        (default: stdin)
        -o --output <path to file>      Specify the output file name. (default: stdout)
        -l --log <path to file>         Optional, specify where the log file needs to be writen to (default: stderr)
        -j --threads <threads>          Optional, specify amount of threads to spawn. Specify the string 'all' to make
                                        demeuk auto detect the amount of threads to start based on the CPU's
                                        (default: all threads).
                                        Note: threading will cost some setup time. Only speeds up for larger files.
        --input-encoding <encoding>     Forces demeuk to decode the input using this encoding (default: en_US.UTF-8).
        --output-encoding <encoding>    Forces demeuk to encoding the output using this encoding (default: en_US.UTF-8).
        -v --verbose                    When set, printing some extra information to stderr. And will print the
                                        lines containing errors to logfile.
        --debug                         When set, the logfile will not only contain lines which caused an error, but
                                        also line which were modified.
        --progress                      Prints out the progress of the demeuk process.
        -n --limit <int>                Limit the number of lines per thread.
        -s --skip <int>                 Skip <int> amount of lines per thread.
        --punctuation <punctuation>     Use to set the punctuation that is use by options. Defaults to:
                                        ! "#$%&'()*+,-./:;<=>?@[\]^_`{|}~
        --version                       Prints the version of demeuk.

    Separating Options:
        -c --cut                        Specify if demeuk should split (default splits on ':'). Returns everything
                                        after the delimiter.
        --cut-before                    Specify if demeuk should return the string before the delimiter.
                                        When cutting, demeuk by default returns the string after the delimiter.
        -f --cut-fields <field>         Specifies the field to be returned, this is in the 'cut' language thus:
                                        N N'th field, N- from N-th field to end line, N-M, from N-th field to M-th
                                        field. -M from start to M-th field.
        -d --delimiter <delimiter>      Specify which delimiter will be used for cutting. Multiple delimiters can be
                                        specified using ','. If the ',' is required for cutting, escape it with a
                                        backslash. Only one delimiter can be used per line.

    Check modules (check if a line matches a specific condition):
        --check-min-length <length>     Requires that entries have a minimal requirement of <length> unicode chars
        --check-max-length <length>     Requires that entries have a maximal requirement of <length> unicode chars
        --check-case                    Drop lines where the uppercase line is not equal to the lowercase line
        --check-controlchar             Drop lines containing control chars.
        --check-email                   Drop lines containing e-mail addresses.
        --check-hash                    Drop lines which are hashes.
        --check-mac-address             Drop lines which are MAC-addresses.
        --check-uuid                    Drop lines which are UUID.
        --check-non-ascii               If a line contain a non ascii char e.g. ü or ç (or everything outside ascii
                                        range) the line is dropped.
        --check-replacement-character   Drop lines containing replacement characters '�'.
        --check-starting-with <string>  Drop lines starting with string, can be multiple strings. Specify multiple
                                        with as comma-seperated list.
        --check-ending-with <string>    Drop lines ending with string, can be multiple strings. Specify multiple
                                        with as comma-seperated list.
        --check-empty-line              Drop lines that are empty or only contain whitespace characters
        --check-regex <string>          Drop lines that do not match the regex. Regex is a comma seperated list of
                                        regexes. Example: [a-z]{1,8},[0-9]{1,8}

    Modify modules (modify a line in place):
        --hex                           Replace lines like: $HEX[41424344] with ABCD.
        --html                          Replace lines like: &#351;ifreyok with şifreyok.
        --html-named                    Replace lines like: &#alpha; Those structures are more like passwords, so
                                        be careful to enable this option.
        --lowercase                     Replace line like 'This Test String' to 'this test string'
        --title-case                    Replace line like 'this test string' to 'This Test String'
        --umlaut                        Replace lines like ko"ffie with an o with an umlaut.
        --mojibake                      Fixes mojibakes, which means lines like SmˆrgÂs will be fixed to Smörgås.
        --encode                        Enables guessing of encoding, based on chardet and custom implementation.
        --tab                           Enables replacing tab char with ':', sometimes leaks contain both ':' and '\t'.
        --newline                       Enables removing newline characters (\r\n) from end and beginning of lines.
        --non-ascii                     Replace non ascii char with their replacement letters. For example ü
                                        becomes u, ç becomes c.
        --trim                          Enables removing newlines representations from end and beginning. Newline
                                        representations detected are '\\n', '\\r', '\n', '\r', '<br>', and '<br />'.

    Add modules (Modify a line, but keep the original as well):
        --add-lower                     If a line contains a capital letter this will add the lower case variant
        --add-latin-ligatures           If a line contains a single ligatures of a latin letter (such as ij), the line
                                        is correct but the original line contain the ligatures is also added to output.
        --add-split                     split on known chars like - and . and add those to the final dictionary.
        --add-umlaut                    In some spelling dicts, umlaut are sometimes written as: o" or i" and not as
                                        one char.
        --add-without-punctuation       If a line contains punctuations, a variant will be added without the
                                        punctuations

    Remove modules (remove specific parts of a line):
        --remove-strip-punctuation      Remove starting and trailing punctuation
        --remove-punctuation            Remove all punctuation in a line
        --remove-email                  Enable email filter, this will catch strings like
                                        1238661:test@example.com:password
    Macro modules:
        -g --googlengram                When set, demeuk will strip universal pos tags: like _NOUN_ or _ADJ
        --leak                          When set, demeuk will run the following modules:
                                            mojibake, encode, newline, check-controlchar
                                        This is recommended when working with leaks and was the default bevarior in
                                        demeuk version 3.11.0 and below.
        --leak-full                     When set, demeuk will run the following modules:
                                            mojibake, encode, newline, check-controlchar,
                                            hex, html, html-named,
                                            check-hash, check-mac-address, check-uuid, check-email,
                                            check-replacement-character, check-empty-line
"""
from binascii import hexlify, unhexlify
from glob import glob
from html import unescape
from inspect import cleandoc
from locale import LC_ALL, setlocale
from math import ceil
from multiprocessing import cpu_count, Pool
from os import linesep, access, path, R_OK, F_OK, W_OK
from re import compile as re_compile
from re import search
from re import split as re_split
from re import sub
from signal import signal, SIGINT, SIG_IGN
from string import punctuation as string_punctuation
from time import sleep
from sys import stderr, stdin, stdout
from unicodedata import category


from chardet import detect
from docopt import docopt
from ftfy import fix_encoding
from ftfy.chardata import HTML_ENTITIES, HTML_ENTITY_RE
from ftfy.fixes import fix_latin_ligatures
from nltk import str2tuple
from nltk.tokenize import WhitespaceTokenizer
from tqdm import tqdm
from unidecode import unidecode


version = '4.2.0'

# Search from start to finish for the string $HEX[], with block of a-f0-9 with even number
# of hex chars. The first match group is repeated.
HEX_REGEX = re_compile(r"^\$(?:HEX|hex)\[((?:[0-9a-fA-F]{2})+)\]$")
EMAIL_REGEX = '.{1,64}@([a-zA-Z0-9_-]{1,63}\\.){1,3}[a-zA-Z]{2,6}'
HASH_HEX_REGEX = '^[a-fA-F0-9]+$'
MAC_REGEX = '^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
UUID_REGEX = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

# Officiale bcrypt hashes hae a bit more fixed size, but saw some weird once:
# $2a$10$demo as example
HASH_BCRYPT_REGEX = '^\\$2[ayb]\\$[0-9]{1,}\\$[\\w\\.\\/]{4,}$'
# Crypt hashes can look a lot like passwords. We do two options here
# $1[$optional salt, max 16]$string of a-zA-Z0-9./ length 7 min till end of line
# $1$a-zA-Z0-9./ min length 12 to make sure we hit somthing like: a-zA-Z0-9./
# this will cause string like $1$JAjdna./d to still be included.

HASH_CRYPT_REGEX = '^\\$[1356]\\$[\\w\\.\\/]{12,}$'
HASH_CRYPT_SALT_REGEX = '^\\$[1356]\\$[\\w\\.\\/\\+]{,16}\\$[\\w\\.\\/]{6,}$'
HASH_PHPBB_REGEX = '^\\$[hH]\\$[\\w\\.\\/]{6,}$'
HASH_REGEX_LIST = [HASH_BCRYPT_REGEX, HASH_CRYPT_SALT_REGEX, HASH_CRYPT_REGEX, HASH_PHPBB_REGEX]

TRIM_BLOCKS = ('\\\\n', '\\\\r', '\\n', '\\r', '<br>', '<br />')

CHUNK_SIZE = 1024 * 1024


def _unescape_fixup_named(match):
    """
    Replace one matched HTML entity with the character it represents,
    if possible.

    Based on: ftfy.fixes._unescape_fixup
    """
    text = match.group(0)
    if text in HTML_ENTITIES:
        return HTML_ENTITIES[text]
    else:
        return text


def _unescape_fixup(match):
    """
    Replace one matched HTML entity with the character it represents,
    if possible.

    Based on: ftfy.fixes._unescape_fixup
    """
    text = match.group(0)
    if text.startswith('&#'):
        unescaped = unescape(text)

        # If html.unescape only decoded part of the string, that's not what
        # we want. The semicolon should be consumed.
        if ';' in unescaped:
            return text
        else:
            return unescaped
    else:
        return text


def clean_googlengram(line):
    """Removes speechtags from line specific to the googlengram module

    Param:
        line (unicode)

    Returns:
        line (unicode)
    """
    return_line = line.split("\t")[0]  # Get the ngram, remove year, counter, etc
    clean = []
    words = WhitespaceTokenizer().tokenize(return_line)
    for word in words:
        # in >1-grams transitions to specific tags are written as:
        # The_ADJ _NOUN_ (meaning from The there is a transition to a noun
        # We remove those
        if word[0] != '_' and word[-1] != '_':
            # Split the token and the tag based on the '_'
            token, tag = str2tuple(word, '_')
            # Punct will be added using rules.
            if len(token) > 1:
                if tag != 'PUNCT' or tag != '.' or tag != '':
                    clean.append(token)
            elif token not in string_punctuation:
                clean.append(token)
    return_line = ' '.join(clean)
    if return_line != line:
        return True, return_line
    else:
        return False, line


def remove_email(line):
    """Removes e-mail addresses from a line.

    Params:
        line (unicode)

    Returns:
        line (unicode)
    """
    if '@' in line:
        if search(f'{EMAIL_REGEX}(:|;)', line):
            return True, sub(f'{EMAIL_REGEX}(:|;)', '', line)
    return False, line


def add_lower(line):
    """Returns if the upper case string is different from the lower case line

    Param:
        line (unicode)

    Returns:
        False if they are the same
        Lowered string if they are not
    """
    line_lower = line.lower()
    if line != line_lower:
        return line_lower
    else:
        return False


def add_latin_ligatures(line):
    """Returns the line cleaned of latin ligatures if there are any.

    Param:
        line (unicode)

    Returns:
        False if there are not any latin ligatures
        Corrected line
    """
    cleaned_line = fix_latin_ligatures(line)
    if line != cleaned_line:
        return cleaned_line
    else:
        return False


def add_without_punctuation(line, punctuation):
    """Returns the line cleaned of punctuation.

    Param:
        line (unicode)

    Returns:
        False if there are not any punctuation
        Corrected line
    """
    cleaned_line = line.translate(str.maketrans('', '', punctuation))

    if line != cleaned_line:
        return cleaned_line
    else:
        return False


def clean_add_umlaut(line):
    """Returns the line cleaned of incorrect umlauting

    Param:
        line (unicode)

    Returns:
        Corrected line
    """
    cleaned_line = line

    umlaut_dict = {
        'a"': 'ä',
        'i"': 'ï',
        'o"': 'ö',
        'u"': 'ü',
        'e"': 'ë',
        'A"': 'Ä',
        'I"': 'Ï',
        'O"': 'Ö',
        'U"': 'Ü',
        'E"': 'Ë',
    }
    for letter in umlaut_dict.keys():
        cleaned_line = cleaned_line.replace(letter, umlaut_dict.get(letter))

    if line != cleaned_line:
        return True, cleaned_line
    else:
        return False, line


def remove_punctuation(line, punctuation):
    """Returns the line without punctuation

    Param:
        line (unicode)
        punctuation (unicode)

    Returns:
        line without start and end punctuation
    """
    return_line = line.translate(str.maketrans('', '', punctuation))
    if return_line != line:
        return True, return_line
    else:
        return False, line


def remove_strip_punctuation(line, punctuation):
    """Returns the line without start and end punctuation

    Param:
        line (unicode)

    Returns:
        line without start and end punctuation
    """
    return_line = line.strip(punctuation)
    if return_line != line:
        return True, return_line
    else:
        return False, line


def add_split(line, punctuation=(' ', '-', r'\.')):
    """Split the line on the punctuation and return elements longer then 1 char.

    Param:
        line (unicode)

    Returns:
        split line
    """
    for p in punctuation:
        if p in line:
            return [i for i in re_split('|'.join(punctuation), line) if len(i) > 1]
    return False


def check_case(line, ignored_chars=(' ', "'", '-')):
    """Checks if an uppercase line is equal to a lowercase line.

    Param:
        line (unicode)
        ignored_chars list(string)

    Returns:
        true if uppercase line is equal to uppercase line
    """
    for c in line:
        c = str(c)
        if c.lower() == c.upper():
            if c in ignored_chars:
                continue
            else:
                return False, c
    return True, None


def check_length(line, min=0, max=0):
    """Does a length check on the line

    Params:
        line (unicode)
        min (int)
        max (int)

    Returns:
        true if length is ok
    """
    status = True
    if min and status:
        status = len(line) >= min
    if max and status:
        status = len(line) < max
    return status


def check_hash(line):
    """Check if a line contains a hash

    Params:
        line (unicode)

    Returns:
        true if line does not contain hash
    """
    if search(HASH_HEX_REGEX, line):
        if len(line) in [32, 40, 64]:
            return False
    if len(line) > 0:
        if line[0] == '$':
            for hash_regex in HASH_REGEX_LIST:
                if search(hash_regex, line):
                    return False
    return True


def check_mac_address(line):
    """Check if a line contains a MAC-address

    Params:
        line (unicode)

    Returns:
        true if line does not contain a MAC-address
    """
    if search(MAC_REGEX, line):
        return False

    return True


def check_email(line):
    """Check if lines contain e-mail addresses with a simple regex

    Params:
        line (unicode)

    Returns:
        true is line does not contain email
    """
    if search(EMAIL_REGEX, line):
        return False
    else:
        return True


def check_non_ascii(line):
    """Checks if a line contains a non ascii chars

    Params:
        line (unicode)

    Returns:
        true if line does not contain non ascii chars
    """
    try:
        line.encode('ascii')
        return True
    except UnicodeEncodeError:
        return False


def check_character(line, character):
    """Checks if a line contains a specific character

    Params:
        line (unicode)

    Returns:
        true if line does contain the specific character

    """
    if character in line:
        return True
    else:
        return False


def check_starting_with(line, strings):
    """Checks if a line start with a specific strings

    Params:
        line (unicode)
        strings[str]

    Returns:
        true if line does start with one of the strings

    """
    for string in strings:
        if line.startswith(string):
            return True
    return False


def check_uuid(line):
    """Check if a line contains a UUID

    Params:
        line (unicode)

    Returns:
        true if line does not contain a UUID
    """
    if search(UUID_REGEX, line):
        return False

    return True


def check_ending_with(line, strings):
    """Checks if a line ends with specific strings

    Params:
        line (unicode)
        strings[str]

    Returns:
        true if line does end with one of the strings

    """
    for string in strings:
        if line.endswith(string):
            return True
    return False


def check_empty_line(line):
    """Checks if a line is empty or only contains whitespace chars

    Params:
        line (unicode)

    Returns:
        true of line is empty or only contains whitespace chars
    """
    if line == '':
        return True
    elif line.isspace():
        return True
    return False


def clean_cut(line, delimiters, fields):
    """Finds the first delimiter and returns the remaining string either after
    or before the delimiter.

    Params:
        line (unicode)
        delimiters list(unicode)
        fields (unicode)

    Returns:
        line (unicode)
    """
    for delimiter in delimiters:
        if delimiter in line:
            if '-' in fields:
                start = fields.split('-')[0]
                stop = fields.split('-')[1]
                if start == '':
                    start = 1
                if stop == '':
                    stop = len(line)
                fields = slice(int(start) - 1, int(stop))
            else:
                fields = slice(int(fields) - 1, int(fields))
            return True, delimiter.join(line.split(delimiter)[fields])
    else:
        return False, line


def clean_non_ascii(line):
    """Replace non ascii chars with there ascii representation.

    Params:
        line (Unicode)

    Returns:
        line (Unicode)
    """
    cleaned_line = unidecode(line)
    if line != cleaned_line:
        return True, cleaned_line
    else:
        return False, line


def clean_lowercase(line):
    """Replace all capitals to lowercase

        Params:
            line (Unicode)

        Returns:
            line (Unicode)

        """
    cleaned_line = line.lower()
    if line != cleaned_line:
        return True, cleaned_line
    else:
        return False, line


def clean_title_case(line):
    """Replace words to title word (uppercasing first letter)

    Params:
        line (Unicode)

    Returns:
        line (Unicode)

    """
    cleaned_line = line.title()
    if line != cleaned_line:
        return True, cleaned_line
    else:
        return False, line


def clean_trim(line):
    """Delete leading and trailing character sequences representing a newline
    from beginning end end of line.

    Params:
        line (Unicode)

    Returns:
        line (Unicode)
    """
    cleaned_line = line
    # Ensure removal of duplicated blocks
    while True:
        has_match = False
        for x in TRIM_BLOCKS:
            if cleaned_line.startswith(x):
                cleaned_line = cleaned_line[len(x):]
                has_match = True

            if cleaned_line.endswith(x):
                cleaned_line = cleaned_line[:-len(x)]
                has_match = True

        if has_match is False:
            break

    if line != cleaned_line:
        return True, cleaned_line
    else:
        return False, line


def clean_tab(line):
    """Replace tab character with ':' greedy

    Params:
        line (bytes)

    Returns:
        line (bytes)
    """
    if b'\x09' in line:
        line = sub(b'\x09+', b'\x3a', line)
        return True, line
    else:
        return False, line


def clean_hex(line):
    """Converts strings like '$HEX[]' to proper binary

    Params:
        line (bytes)

    Returns:
        line (bytes)
    """
    match = HEX_REGEX.search(line)
    if match:
        return True, unhexlify(match.group(1))
    else:
        return False, line


def clean_html(line):
    """Detects html encode chars and decodes them

    Params:
        line (Unicode)

    Returns:
        line (Unicode)
    """
    return_line = HTML_ENTITY_RE.sub(_unescape_fixup, line)
    if return_line != line:
        return True, return_line
    else:
        return False, line


def clean_html_named(line):
    """Detects named html encode chars and decodes them

    Params:
        line (Unicode)

    Returns:
        line (Unicode)
    """
    return_line = HTML_ENTITY_RE.sub(_unescape_fixup_named, line)
    if return_line != line:
        return True, return_line
    else:
        return False, line


def clean_newline(line):
    """Delete newline characters at start and end of line

    Params:
        line (Unicode)

    Returns:
        line (Unicode)
    """
    return_line = line.strip('\r\n')
    if return_line != line:
        return True, return_line
    else:
        return False, line


def check_controlchar(line):
    """Detects control chars, returns True when detected

    Params:
        line (Unicode)

    Returns:
        Status, String
    """
    for c in line:
        # https://en.wikipedia.org/wiki/Unicode_character_property#General_Category
        # Characters (they have meaning):
        # Cc -> Control Char (End of stream)
        # Cf -> Control flow (right to left)
        # Non chars:
        # Cn -> Not assigned
        # Co -> Private use
        # Cs -> Surrogate
        if category(c) in ['Cc', 'Cf', 'Cn', 'Co', 'Cs']:
            return True, c
    return False, None


def check_regex(line, regex):
    """Checks if a line matches a list of regexes

    Params:
        line (unicode)
        regex (list)

    Returns:
        true if all regexes match
        false if line does not match regex
    """
    for regex in regex:
        if search(regex, line):
            continue
        else:
            return False
    return True


def try_encoding(line, encoding):
    """Tries to decode a line using supplied encoding

    Params:
        line (Byte): byte variable that will be decoded
        encoding (string): the encoding to be tried

    Returns:
        False if decoding failed
        String if decoding worked
    """
    try:
        # Try to decode the line
        line_decoded = line.decode(encoding)
        # Some encoding will decoded almost any line, lets check if we have invalid chars.
        # If we have invalid chars (except for tab like chars) we will fail
        for c in line_decoded:
            if category(c) in ['Cc', 'Cf', 'Cn', 'Co', 'Cs']:
                if c == '\t' or c == '\f':
                    continue
                else:
                    return False
        return line_decoded
    except UnicodeDecodeError:
        return False


def clean_mojibake(line):
    """Detects mojibake and tries to correct it.
    Mojibake are string that are decoded incorrectly and then encoded incorrectly.
    This results in strings like: Ãºnico which should be único.

    Param:
        line (str)

    Returns:
        Cleaned string
    """
    return_line = fix_encoding(line)
    if return_line != line:
        return True, return_line
    else:
        return False, line


def clean_encode(line, input_encoding):
    """Detects and tries encoding

    Params:
        line (bytes)

    Returns:
        Decoded UTF-8 string
    """
    # Try either a user set of encodings or the default encoding set.
    # When using multiple encoding is it beter to have multibyte encodings before
    # Single byte encodings. Also it is beter to not include iso encoding by default.
    # https://en.wikipedia.org/wiki/Character_encoding#Common_character_encodings
    # Input_encoding is by default [utf8]
    for encoding in input_encoding:
        line_decoded = try_encoding(line, encoding)
        if line_decoded is not False:
            break
    # All other methods failed, lets run the detect library on the line and try to guess the encoding.
    if line_decoded is False:
        encode = detect(line)
        if encode.get('encoding'):
            try:
                line_decoded = line.decode(encode['encoding'])
            except (UnicodeDecodeError, LookupError) as e: # noqa F841
                return False, encode["encoding"]
        else:
            return False, 'Unknown'
    # If we managed to get here, return decode line
    return True, line_decoded


def clean_up(lines):
    """Main clean loop, this calls all the other clean functions.

    Args:
        line(bytes): Line to be cleaned up

    Returns:
        (str(Decoded line), str(Failed line))
    """
    results = []
    log = []

    for line in lines:
        # Check if the limit is set, if so minus 1 and if 0 is reached lets quit.
        if type(config['limit']) is int:
            if config['limit'] > 0:
                config['limit'] -= 1
            else:
                break

        # When stop is set all demeuking module will be skipped for this line.
        stop = False
        if config['debug']:
            log.append(f'----BEGIN---- {hexlify(line)}{linesep}')
        # Replace tab chars as ':' greedy
        if config.get('tab') and not stop:
            status, line = clean_tab(line)
            if status and config['debug']:
                log.append(f'Clean_tab; replaced tab characters; {line}{linesep}')
        # Converting enoding to UTF-8
        if config.get('encode') and not stop:
            status, line_decoded = clean_encode(line, config.get('input_encoding'))
            if status is False:
                log.append(f'Clean_encode; decoding error with {line_decoded}; {line}{linesep}')
                stop = True
            elif status is True and config['debug']:
                log.append(f'Clean_encode; decoded line; {line_decoded}{linesep}')
        else:
            try:
                line_decoded = line.decode(config.get('input_encoding')[0])
                if config['debug']:
                    log.append(f'Clean_up; decoded using input_encoding option; {line_decoded}{linesep}')
            except (UnicodeDecodeError) as e: # noqa F841
                log.append(f'Clean_up; decoding error with unknown; {line}{linesep}')
                stop = True
        # From here it is expected that line is correctly decoded!
        # Check if some lines contain a hex string like $HEX[41424344]
        if config.get('hex') and not stop:
            status, line_decoded = clean_hex(line_decoded)
            if status:
                # Lines contains hex, this function will return binary string, so add it back to
                # our undecoded lines
                lines.append(line_decoded)
                if config['debug']:
                    log.append(f'Clean_hex; replaced $HEX[], added to queue and quiting; {line}{linesep}')
                # Aborting future processing of this line.
                stop = True

        # Check if there are html char in the line, decode them if there are
        if config.get('html') and not stop:
            status, line_decoded = clean_html(line_decoded)
            if status:
                # Line contains html string, because this can be binary data (linefeeds etc)
                # convert back to binary string and add to queue again.
                lines.append(line_decoded.encode())
                if config['debug']:
                    log.append(f'Clean_html; replaced html, added to queue and quiting; {line_decoded}{linesep}')
                stop = True

        # Checks if there are any mojibakes inside the line
        # You must mojibake before removing control chars! Some control chars
        # are part of a valid mojibake.
        if config.get('mojibake') and not stop:
            status, line_decoded = clean_mojibake(line_decoded)
            if status and config['debug']:
                log.append(f'Clean_mojibake; found a mojibake; {line}{linesep}')

        # Delete leading and trailing newline characters
        if config.get('newline') and not stop:
            status, line_decoded = clean_newline(line_decoded)
            if status and config['debug']:
                log.append(f'Clean_newline; deleted newline characters; {line_decoded!r}{linesep}')

        # Checks if there are any control chars inside line
        if config.get('check-controlchar') and not stop:
            status, cc = check_controlchar(line_decoded)
            if status:
                # Control char detected
                log.append(f'Check_controlchar; found controlchar {cc!r}; {line_decoded!r}{linesep}')
                stop = True

        # Check if there are named html chars in the line
        if config.get('html-named') and not stop:
            status, line_decoded = clean_html_named(line_decoded)
            if status and config['debug']:
                log.append(f'Clean_html_named; found named html character; {line_decoded}{linesep}')

        # Delete leading and trailing character sequences representing a newline
        if config.get('trim') and not stop:
            status, line_decoded = clean_trim(line_decoded)
            if status and config['debug']:
                log.append(f'Clean_trim; found trim sequence; {line_decoded!r}{linesep}')

        # Should we do the cut?
        if config.get('cut') and not stop:
            status, line_decoded = clean_cut(line_decoded, config['delimiter'], config['cut-fields'])
            if status and config['debug']:
                log.append(f'Clean_cut; field cutted; {line_decoded}{linesep}')

        # Replace umlauts
        if config.get('umlaut') and not stop:
            status, line_decoded = clean_add_umlaut(line_decoded)
            if status and config['debug']:
                log.append(f'Clean_umlaut; umlaut replaced; {line_decoded}{linesep}')

        # Replace non-ascii
        if config.get('non-ascii') and not stop:
            status, line_decoded = clean_non_ascii(line_decoded)
            if status and config['debug']:
                log.append(f'Clean_non_ascii; non-ascii replaced; {line_decoded}{linesep}')

        # Replace all letters with lowercase
        if config.get('lowercase') and not stop:
            status, line_decoded = clean_lowercase(line_decoded)
            if status and config['verbose']:
                log.append(f'Clean_lowercase; all capitals replaced; {line_decoded}{linesep}')

        # Replace first letter of a word to a uppercase letter
        if config.get('title-case') and not stop:
            status, line_decoded = clean_title_case(line_decoded)
            if status and config['debug']:
                log.append(f'Clean_title_case; non-ascii replaced; {line_decoded}{linesep}')

        # Should we remove emails?
        if config.get('remove-email') and not stop:
            status, line_decoded = remove_email(line_decoded)
            if status and config['debug']:
                log.append(f'Remove_email; email found; {line_decoded}{linesep}')

        if config.get('googlengram') and not stop:
            status, line_decoded = clean_googlengram(line_decoded)
            if status and config['debug']:
                log.append(f'Clean_googlengram; tos found and removed; {line_decoded}{linesep}')

        if config.get('check-case') and not stop:
            status, c = check_case(line_decoded)
            if not status:
                log.append(f'Check_case; dropped line because of {c}; {line_decoded}{linesep}')
                stop = True

        if config.get('check-length') and not stop:
            if not check_length(line_decoded, min=config['check-min-length'], max=config['check-max-length']):
                log.append(f'Check_length; dropped line because of failed length check; {line_decoded}{linesep}')
                stop = True

        if config.get('check-email') and not stop:
            if not check_email(line_decoded):
                log.append(f'Check_email; dropped line because found email; {line_decoded}{linesep}')
                stop = True

        if config.get('check-hash') and not stop:
            if not check_hash(line_decoded):
                log.append(f'Check_hash; dropped line because found a hash; {line_decoded}{linesep}')
                stop = True

        if config.get('check-mac-address') and not stop:
            if not check_mac_address(line_decoded):
                log.append(f'Check_mac_address; dropped line because found a MAC address; {line_decoded}{linesep}')
                stop = True

        if config.get('check-non-ascii') and not stop:
            if not check_non_ascii(line_decoded):
                log.append(f'Check_non_ascii; dropped line because non ascii char found; {line_decoded}{linesep}')
                stop = True

        if config.get('check-replacement-character') and not stop:
            if check_character(line_decoded, '�'):
                log.append(f'Check_replacement_character; dropped line because "�" found; {line_decoded}{linesep}')
                stop = True

        if config.get('check-regex') and not stop:
            if not check_regex(line_decoded, config.get('check-regex')):
                log.append(f'Check_regex; dropped line because it does not match the regex; {line_decoded}{linesep}')
                stop = True

        if config.get('check-starting-with') and not stop:
            to_check = config.get("check-starting-with")
            if check_starting_with(line_decoded, to_check):
                log.append(f'Check_starting_with; dropped line because {to_check} found; {line_decoded}{linesep}')
                stop = True

        if config.get('check-uuid') and not stop:
            if not check_uuid(line_decoded):
                log.append(f'Check_uuid; dropped line because found a uuid; {line_decoded}{linesep}')
                stop = True

        if config.get('check-ending-with') and not stop:
            to_check = config.get("check-ending-with")
            if check_ending_with(line_decoded, to_check):
                log.append(f'Check_ending_with; dropped line because {to_check} found; {line_decoded}{linesep}')
                stop = True

        if config.get('check-empty-line') and not stop:
            if check_empty_line(line_decoded):
                log_line = "Check_empty_line; dropped line because is empty or only contains whitespace;"
                log.append(f'{log_line} {line_decoded}{linesep}')
                stop = True

        if config.get('remove-punctuation') and not stop:
            status, line_decoded = remove_punctuation(line_decoded, config.get('punctuation'))
            if status and config['debug']:
                log.append(f'Remove_punctuation; stripped punctuation; {line_decoded}{linesep}')

        if config.get('remove-strip-punctuation') and not stop:
            status, line_decoded = remove_strip_punctuation(line_decoded, config.get('punctuation'))
            if status and config['debug']:
                log.append(f'Remove_strip_punctuation; stripped punctuation; {line_decoded}{linesep}')

        # We ran all modules
        if not stop:
            # Some clean modules will modify the end result, those modification will be added here.
            # They will be added to the running thread, this might cause one thread to have more work
            # then others.
            if config.get('add-split'):
                modified_lines = add_split(line_decoded)
                if modified_lines:
                    for modified_line in modified_lines:
                        if config['debug']:
                            log.append(f'Add_split; new line because of split; {modified_line}{linesep}')
                        lines.append(modified_line.encode())

            if config.get('add-lower'):
                modified_line = add_lower(line_decoded)
                if modified_line:
                    if config['debug']:
                        log.append(f'Add_lower; new line; {modified_line}{linesep}')
                    lines.append(modified_line.encode())

            if config.get('add-latin-ligatures'):
                modified_line = add_latin_ligatures(line_decoded)
                if modified_line:
                    if config['debug']:
                        log.append(f'Add_latin_ligatures; new line; {modified_line}{linesep}')
                    lines.append(modified_line.encode())

            if config.get('add-umlaut'):
                status, modified_line = clean_add_umlaut(line_decoded)
                if status:
                    if config['debug']:
                        log.append(f'Add_umlaut; new line; {modified_line}{linesep}')
                    lines.append(modified_line.encode())

            if config.get('add-without-punctuation'):
                modified_line = add_without_punctuation(line_decoded, config.get('punctuation'))
                if modified_line:
                    if config['debug']:
                        log.append(f'Add_without_punctuation; new line; {modified_line}{linesep}')
                    lines.append(modified_line.encode())

            if config['debug']:
                log.append(f'----End---- {line_decoded}{linesep}{linesep}')
            results.append(f'{line_decoded}{linesep}')

    return ({'results': results, 'log': log})


def chunkify(filename, size=CHUNK_SIZE):
    with open(filename, 'rb') as fh:
        for x in range(0, config.get('skip')):
            fh.readline()

        while True:
            lines = [line.rstrip(b'\n') for line in fh.readlines(size)]
            yield lines
            if len(lines) == 0:
                break


# Quick to default logging to stderr instead
def stderr_print(*args, **kwargs):
    if config['verbose'] is True:
        kwargs.setdefault('file', stderr)
        print(*args, **kwargs)


def main():
    #
    # Config parser
    arguments = docopt(cleandoc('\n'.join(__doc__.split('\n')[2:])))

    if arguments.get('--version'):
        print(f'demeuk - {version}')
        exit()

    input_file = arguments.get('--input')
    output_file = arguments.get('--output')
    log_file = arguments.get('--log')

    if arguments.get('--threads'):
        a_threads = arguments.get('--threads')
        if a_threads == 'all':
            a_threads = cpu_count()
        else:
            a_threads = int(a_threads)
    else:
        a_threads = cpu_count()

    # Lets create the default config
    global config
    config = {
        'input_encoding': ['UTF-8'],
        'cut': False,
        'delimiter': ':',
        'cut-fields': '2-',
        'verbose': False,
        'debug': False,
        'progress': False,
        'limit': False,
        'skip': False,

        # Modify
        'encode': False,
        'mojibake': False,
        'tab': False,
        'trim': False,
        'newline': False,
        'hex': False,
        'html': False,
        'html-named': False,
        'umlaut': False,
        'non-ascii': False,
        'title_case': False,

        # Check
        'length': False,
        'check-min-length': 0,
        'check-max-length': 0,
        'check-controlchar': False,
        'check-case': False,
        'check-email': False,
        'check-hash': False,
        'check-mac-address': False,
        'check-non-ascii': False,
        'check-replacement-character': False,
        'check-starting-with': False,
        'check-uuid': False,
        'check-ending-with': False,
        'check-empty-line': False,
        'check-regex': False,

        # Add
        'add-lower': False,
        'add-latin-ligatures': False,
        'add-split': False,
        'add-umlaut': False,
        'add-without-punctuation': False,

        # Remove
        'remove-strip-punctuation': False,
        'remove-punctuation': False,
        'remove-email': False,
    }

    # Default modules
    if arguments.get('--verbose'):
        config['verbose'] = True

    if arguments.get('--debug'):
        config['debug'] = True

    if arguments.get('--progress'):
        if config['verbose'] or config['debug']:
            if not log_file:
                stderr_print('Progress can not be used with verbose or debug')
                exit(2)
        if not input_file:
            # Forcing printing error message
            config['verbose'] = True
            stderr_print('Progress can not be used when using stdin.')
            exit(2)
        config['progress'] = True

    if arguments.get('--force'):
        config['force'] = True

    if arguments.get('--limit'):
        config['limit'] = int(arguments.get('--limit'))

    if arguments.get('--skip'):
        config['skip'] = int(arguments.get('--skip'))

    if arguments.get('--input-encoding'):
        config['input_encoding'] = arguments.get('--input-encoding').split(',')

    if arguments.get('--output-encoding'):
        setlocale(LC_ALL, arguments.get('--output-encoding'))
    else:
        setlocale(LC_ALL, 'en_US.UTF-8')

    if arguments.get('--punctuation'):
        config['punctuation'] = arguments.get('--punctuation')
    else:
        config['punctuation'] = string_punctuation + ' '

    if arguments.get('--cut'):
        config['cut'] = True

    if arguments.get('--delimiter'):
        splitter = ','
        if len(arguments.get('--delimiter')) >= 1:
            if arguments.get('--delimiter')[0] == ',':
                splitter = ';'
        config['delimiter'] = arguments.get('--delimiter').split(splitter)

    if arguments.get('--cut-before'):
        config['cut-fields'] = '-1'

    if arguments.get('--cut-fields'):
        config['cut-fields'] = arguments.get('--cut-fields')

    # Clean / modify modules
    if arguments.get('--hex'):
        config['hex'] = True

    if arguments.get('--html'):
        config['html'] = True

    if arguments.get('--html-named'):
        config['html-named'] = True

    if arguments.get('--umlaut'):
        config['umlaut'] = True

    if arguments.get('--non-ascii'):
        config['non-ascii'] = True

    if arguments.get('--lowercase'):
        config['lowercase'] = True

    if arguments.get('--title-case'):
        config['title-case'] = True

    if arguments.get('--mojibake'):
        config['mojibake'] = True

    if arguments.get('--encode'):
        config['encode'] = True

    if arguments.get('--tab'):
        config['tab'] = True

    if arguments.get('--newline'):
        config['newline'] = True

    if arguments.get('--trim'):
        config['trim'] = True

    # Check modules
    if arguments.get('--check-min-length'):
        config['check-length'] = True
        config['check-min-length'] = int(arguments.get('--check-min-length'))

    if arguments.get('--check-max-length'):
        config['check-length'] = True
        config['check-max-length'] = int(arguments.get('--check-max-length'))

    if arguments.get('--check-case'):
        config['check-case'] = True

    if arguments.get('--check-email'):
        config['check-email'] = True

    if arguments.get('--check-hash'):
        config['check-hash'] = True

    if arguments.get('--check-mac-address'):
        config['check-mac-address'] = True

    if arguments.get('--check-non-ascii'):
        config['check-non-ascii'] = True

    if arguments.get('--check-replacement-character'):
        config['check-replacement-character'] = True

    if arguments.get('--check-starting-with'):
        if ',' in arguments.get('--check-starting-with'):
            config['check-starting-with'] = arguments.get('--check-starting-with').split(',')
        else:
            config['check-starting-with'] = [arguments.get('--check-starting-with')]

    if arguments.get('--check-uuid'):
        config['check-uuid'] = True

    if arguments.get('--check-ending-with'):
        if ',' in arguments.get('--check-ending-with'):
            config['check-ending-with'] = arguments.get('--check-ending-with').split(',')
        else:
            config['check-ending-with'] = [arguments.get('--check-ending-with')]

    if arguments.get('--check-empty-line'):
        config['check-empty-line'] = True

    if arguments.get('--check-controlchar'):
        config['check-controlchar'] = True

    if arguments.get('--check-regex'):
        config['check-regex'] = arguments.get('--check-regex').split(',')

    # Add modules
    if arguments.get('--add-lower'):
        config['add-lower'] = True

    if arguments.get('--add-latin-ligatures'):
        config['add-latin-ligatures'] = True

    if arguments.get('--add-split'):
        config['add-split'] = True

    if arguments.get('--add-umlaut'):
        config['add-umlaut'] = True

    if arguments.get('--add-without-punctuation'):
        config['add-without-punctuation'] = True

    # Remove modules
    if arguments.get('--remove-strip-punctuation'):
        config['remove-strip-punctuation'] = True

    if arguments.get('--remove-email'):
        config['remove-email'] = True

    if arguments.get('--remove-punctuation'):
        config['remove-punctuation'] = True

    # Some meta-modules, those overwrite settings
    if arguments.get('--googlengram'):
        config['cut'] = False
        config['remove-email'] = False
        config['encode'] = True
        config['mojibake'] = False
        config['check-controlchar'] = False
        config['tab'] = False
        config['googlengram'] = True

    # Meta-module for leak files. Set the following defaults:
    # mojibake, encode, newline, check-controlchar
    if arguments.get('--leak'):
        config['mojibake'] = True
        config['encode'] = True
        config['newline'] = True
        config['check-controlchar'] = True

    # Meta-module for leak fils, but more modules. Set the following defaults:
    # --mojibake, --encode, --newline, --check-controlchar,
    # --hex, --html, --html-named,
    # --check-hash, --check-mac-address, --check-uuid, --check-email,
    # --check-replacement-character, --check-empty-line
    if arguments.get('--leak-full'):
        config['mojibake'] = False
        config['encode'] = True
        config['newline'] = True
        config['check-controlchar'] = True
        config['hex'] = True
        config['html'] = True
        config['html-named'] = True
        config['check-hash'] = True
        config['check-mac-address'] = True
        config['check-uuid'] = True
        config['check-email'] = True
        config['check-replacement-character'] = True
        config['check-empty-line'] = True

    if output_file and not access(path.dirname(output_file), W_OK):
        stderr_print(f"Cannot write output file to {path(output_file)}")
    # check if logfile exists, or that the directory of the log file is at least writable.
    if log_file and not (access(log_file, F_OK) or access(path.dirname(log_file), W_OK)):
        stderr_print(f"Cannot write log file to {log_file}")
    if input_file and not access(input_file, R_OK):
        stderr_print(f"Cannot read input file to {input_file}")

    #  Main worker
    stderr_print(f'Main: running demeuk - {version}')

    stderr_print(f'Main: Using {a_threads} core(s) of total available cores: {cpu_count()}')

    stderr_print(f'Main: start chunking file {input_file}')
    if output_file:
        stderr_print(f'Main: output found in {output_file}')
    if log_file:
        stderr_print(f'Main: logs found in {log_file}')

    stderr_print('Main: done chunking file.')
    stderr_print('Main: processing started.')

    if output_file:
        p_output_file = open(output_file, 'w')
    else:
        p_output_file = stdout

    if log_file:
        p_log_file = open(log_file, 'a')
    else:
        p_log_file = stderr

    def write_results(results):
        p_output_file.writelines(results)
        p_output_file.flush()

    def write_log(log):
        if config['debug'] or config['verbose'] or log_file:
            p_log_file.writelines(log)
            p_log_file.flush()

    def write_results_and_log(async_result):
        write_results(async_result['results'])
        write_log(async_result['log'])

    def init_worker():
        signal(SIGINT, SIG_IGN)

    def process_jobs(chunk_start):
        # Cut file in to chunks and process each trunk multi-threaded
        while True:
            while True:
                # Process completed jobs in-order
                if jobs and jobs[0].ready():
                    # Housekeeping cleanup jobs completed from the list
                    job = jobs.pop(0)
                    write_results_and_log(job.get())
                else:
                    break

            # Find out which jobs are running
            running_jobs = sum([not job.ready() for job in jobs])
            if running_jobs < a_threads:
                job = pool.apply_async(clean_up, (chunk,))
                chunk_start += len(chunk)
                jobs.append(job)
                break
            else:
                # Wait a little while for available spacing within Pool
                sleep(1)

    write_log(f'Running demeuk - {version}{linesep}')
    with Pool(a_threads, init_worker) as pool:
        jobs = []
        # chunk_start will be the started value of the combined output lines
        chunk_start = 0
        if input_file:
            # Process files based on input glob
            for filename in tqdm(glob(input_file, recursive=True), desc='Files processed', mininterval=0.1,
                                 unit=' files', disable=not config.get('progress'), position=0):
                if not access(filename, R_OK):
                    continue
                chunks_estimate = int(ceil(path.getsize(filename) / CHUNK_SIZE))
                for chunk in tqdm(chunkify(filename, CHUNK_SIZE), desc='Chunks processed', mininterval=1,
                                  unit=' chunks', disable=not config.get('progress'), total=chunks_estimate,
                                  position=1):
                    process_jobs(chunk_start)
            stderr_print('Main: done submitting all jobs, waiting for threads to finish')
            while len(jobs) > 0:
                job = jobs.pop(0)
                job.wait()
                write_results_and_log(job.get())
        else:
            # Read chunk amount from stdin
            chunks = stdin.readlines(CHUNK_SIZE)
            while chunks:
                chunk = [line.rstrip('\n').encode(config['input_encoding'][0]) for line in chunks]
                process_jobs(chunk_start)

                chunks = stdin.readlines(CHUNK_SIZE)

            stderr_print('Main: done submitting all jobs, waiting for threads to finish')
            while len(jobs) > 0:
                job = jobs.pop(0)
                job.wait()
                write_results_and_log(job.get())

    stderr_print('Main: all done')
    if output_file:
        p_output_file.close()
    if log_file:
        p_log_file.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        stderr_print("ERROR: Process terminated by user! (CTRL+C)")
        exit(3)
