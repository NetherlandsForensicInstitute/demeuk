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
        --check-min-digits <count>      Require that entries contain at least <count> digits
                                        (following the Python definition of a digit,
                                        see https://docs.python.org/3/library/stdtypes.html#str.isdigit)
        --check-max-digits <count>      Require that entries contain at most <count> digits
                                        (following the Python definition of a digit,
                                        see https://docs.python.org/3/library/stdtypes.html#str.isdigit)
        --check-min-uppercase <count>   Require that entries contain at least <count> uppercase letters
                                        (following the Python definition of uppercase,
                                        see https://docs.python.org/3/library/stdtypes.html#str.isupper)
        --check-max-uppercase <count>   Require that entries contain at most <count> uppercase letters
                                        (following the Python definition of uppercase,
                                        see https://docs.python.org/3/library/stdtypes.html#str.isupper)
        --check-min-specials <count>    Require that entries contain at least <count> specials
                                        (a special is defined as a non whitespace character which is not alphanumeric,
                                        following the Python definitions of both,
                                        see https://docs.python.org/3/library/stdtypes.html#str.isspace
                                        and https://docs.python.org/3/library/stdtypes.html#str.isalnum)
        --check-max-specials <count>    Require that entries contain at most <count> specials
                                        (a special is defined as a non whitespace character which is not alphanumeric,
                                        following the Python definitions of both,
                                        see https://docs.python.org/3/library/stdtypes.html#str.isspace
                                        and https://docs.python.org/3/library/stdtypes.html#str.isalnum)


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
import argparse
from binascii import hexlify, unhexlify
from glob import glob
from html import unescape
from io import BytesIO
from math import ceil
from multiprocessing import Manager, Process, cpu_count
from os import linesep, access, path, R_OK, W_OK, F_OK
import os
from re import compile as re_compile
from re import search
from re import split as re_split
from re import sub
import re
from string import punctuation as string_punctuation
from sys import stderr, stdout, exit, stdin
from typing import Any, BinaryIO, Callable, Literal, TypedDict
from unicodedata import category


from chardet import detect
from ftfy import fix_encoding
from ftfy.chardata import HTML_ENTITIES, HTML_ENTITY_RE
from ftfy.fixes import fix_latin_ligatures
from nltk import str2tuple
from nltk.tokenize import WhitespaceTokenizer
from tqdm import tqdm
from unidecode import unidecode

# Type hinting
HTML_ENTITIES: dict[str, str]


# Configuration TypedDict
class Config(TypedDict):
    input_encoding: list[str]
    output_encoding: str
    cut: bool
    delimiter: str | list[str]
    cut_fields: str
    verbose: bool
    debug: bool
    progress: bool
    limit: bool | int
    skip: bool | int
    encode: bool
    mojibake: bool
    tab: bool
    trim: bool
    newline: bool
    hex: bool
    html: bool
    html_named: bool
    umlaut: bool
    non_ascii: bool
    title_case: bool
    lowercase: bool
    punctuation: str
    check_length: bool
    check_min_length: int
    check_max_length: int
    check_controlchar: bool
    check_case: bool
    check_email: bool
    check_hash: bool
    check_mac_address: bool
    check_non_ascii: bool
    check_replacement_character: bool
    check_starting_with: Literal[False] | list[str]
    check_uuid: bool
    check_ending_with: Literal[False] | list[str]
    check_empty_line: bool
    check_regex: Literal[False] | list[str]
    check_min_digits: int
    check_max_digits: int | float
    check_min_uppercase: int
    check_max_uppercase: float | int
    check_min_specials: int
    check_max_specials: float | int
    add_lower: bool
    add_latin_ligatures: bool
    add_split: bool
    add_umlaut: bool
    add_without_punctuation: bool
    remove_strip_punctuation: bool
    remove_punctuation: bool
    remove_email: bool

    googlengram: bool
    leak: bool
    leak_full: bool

class InputFileData(TypedDict):
    filename: str | BinaryIO
    chunk_estimation: int

version = "4.3.0"

# Search from start to finish for the string $HEX[], with block of a-f0-9 with even number
# of hex chars. The first match group is repeated.
HEX_REGEX = re_compile(r"^\$(?:HEX|hex)\[((?:[0-9a-fA-F]{2})+)\]$")
EMAIL_REGEX = r"[a-zA-Z0-9](?:[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]{0,62}[a-zA-Z0-9])?@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*(?:\.[a-zA-Z]{2,6})+"
HASH_HEX_REGEX = "^[a-fA-F0-9]+$"
MAC_REGEX = "^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
UUID_REGEX = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"

# Officiale bcrypt hashes hae a bit more fixed size, but saw some weird once:
# $2a$10$demo as example
HASH_BCRYPT_REGEX = "^\\$2[ayb]\\$[0-9]{1,}\\$[\\w\\.\\/]{4,}$"
# Crypt hashes can look a lot like passwords. We do two options here
# $1[$optional salt, max 16]$string of a-zA-Z0-9./ length 7 min till end of line
# $1$a-zA-Z0-9./ min length 12 to make sure we hit somthing like: a-zA-Z0-9./
# this will cause string like $1$JAjdna./d to still be included.

HASH_CRYPT_REGEX = "^\\$[1356]\\$[\\w\\.\\/]{12,}$"
HASH_CRYPT_SALT_REGEX = "^\\$[1356]\\$[\\w\\.\\/\\+]{,16}\\$[\\w\\.\\/]{6,}$"
HASH_PHPBB_REGEX = "^\\$[hH]\\$[\\w\\.\\/]{6,}$"
HASH_REGEX_LIST = [HASH_BCRYPT_REGEX, HASH_CRYPT_SALT_REGEX, HASH_CRYPT_REGEX, HASH_PHPBB_REGEX]

TRIM_BLOCKS = ("\\\\n", "\\\\r", "\\n", "\\r", "<br>", "<br />")

CHUNK_SIZE = 1024 * 1024  # 1MB


def _unescape_fixup_named(match: re.Match[str]):
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


def _unescape_fixup(match: re.Match[str]):
    """
    Replace one matched HTML entity with the character it represents,
    if possible.

    Based on: ftfy.fixes._unescape_fixup
    """
    text = match.group(0)
    if text.startswith("&#"):
        unescaped = unescape(text)

        # If html.unescape only decoded part of the string, that's not what
        # we want. The semicolon should be consumed.
        if ";" in unescaped:
            return text
        else:
            return unescaped
    else:
        return text


def clean_googlengram(line: str):
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
        if word[0] != "_" and word[-1] != "_":
            # Split the token and the tag based on the '_'
            token, tag = str2tuple(word, "_")
            # Punct will be added using rules.
            if len(token) > 1:
                if tag != "PUNCT" and tag != "." and tag != "":
                    clean.append(token)
            elif token not in string_punctuation:
                clean.append(token)
    return_line = " ".join(clean)
    if return_line != line:
        return True, return_line
    else:
        return False, line


def remove_email(line: str):
    """Removes e-mail addresses from a line.

    Params:
        line (unicode)

    Returns:
        line (unicode)
    """
    if "@" in line:
        if search(f"{EMAIL_REGEX}(:|;)?", line):
            return True, sub(f"{EMAIL_REGEX}(:|;)?", "", line)
    return False, line


def add_lower(line: str):
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


def add_latin_ligatures(line: str) -> str | Literal[False]:
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


def add_without_punctuation(line: str, punctuation: str):
    """Returns the line cleaned of punctuation.

    Param:
        line (unicode)

    Returns:
        False if there are not any punctuation
        Corrected line
    """
    cleaned_line = line.translate(str.maketrans("", "", punctuation))

    if line != cleaned_line:
        return cleaned_line
    else:
        return False


def clean_add_umlaut(line: str):
    """Returns the line cleaned of incorrect umlauting

    Param:
        line (unicode)

    Returns:
        Corrected line
    """
    cleaned_line = line

    umlaut_dict = {
        'a"': "ä",
        'i"': "ï",
        'o"': "ö",
        'u"': "ü",
        'e"': "ë",
        'A"': "Ä",
        'I"': "Ï",
        'O"': "Ö",
        'U"': "Ü",
        'E"': "Ë",
    }
    for letter, new_letter in umlaut_dict.items():
        cleaned_line = cleaned_line.replace(letter, new_letter)

    if line != cleaned_line:
        return True, cleaned_line
    else:
        return False, line


def remove_punctuation(line: str, punctuation: str):
    """Returns the line without punctuation

    Param:
        line (unicode)
        punctuation (unicode)

    Returns:
        line without start and end punctuation
    """
    return_line = line.translate(str.maketrans("", "", punctuation))
    if return_line != line:
        return True, return_line
    else:
        return False, line


def remove_strip_punctuation(line: str, punctuation: str):
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


def add_split(
    line: str,
    punctuation: tuple[str, ...] = (
        " ",
        "-",
        r"\.",
        ":",
        "_",
        ",",
        ";",
        "!",
        r"\?",
        r"\(",
        r"\)",
        r"\[",
        r"\]",
        r"\{",
        r"\}",
        r"\\",
        "/",
        r"\'",
        r"\"",
        "#",
        r"\$",
        "%",
        "&",
        r"\*",
        r"\+",
        "=",
        r"\^",
        "~",
        r"\|",
        "@",
        "<",
        ">",
        r"`",
    ),
):
    """Split the line on the punctuation and return elements longer then 1 char.

    Param:
        line (unicode)

    Returns:
        split line
    """
    for p in punctuation:
        if p in line:
            return [i for i in re_split("|".join(punctuation), line) if len(i) > 1]
    return False


def check_case(line: str, ignored_chars: tuple[str, ...] = (" ", "'", "-")):
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


def check_length(line: str, min: int = 0, max: int = 0):
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


def check_hash(line: str):
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
        if line[0] == "$":
            for hash_regex in HASH_REGEX_LIST:
                if search(hash_regex, line):
                    return False
    return True


def check_mac_address(line: str):
    """Check if a line contains a MAC-address

    Params:
        line (unicode)

    Returns:
        true if line does not contain a MAC-address
    """
    if search(MAC_REGEX, line):
        return False

    return True


def check_email(line: str):
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


def check_non_ascii(line: str):
    """Checks if a line contains a non ascii chars

    Params:
        line (unicode)

    Returns:
        true if line does not contain non ascii chars
    """
    try:
        line.encode("ascii")
        return True
    except UnicodeEncodeError:
        return False


def check_character(line: str, character: str):
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


def check_starting_with(line: str, strings: list[str]):
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


def check_uuid(line: str):
    """Check if a line contains a UUID

    Params:
        line (unicode)

    Returns:
        true if line does not contain a UUID
    """
    if search(UUID_REGEX, line):
        return False

    return True


def check_ending_with(line: str, strings: list[str]):
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


def check_empty_line(line: str):
    """Checks if a line is empty or only contains whitespace chars

    Params:
        line (unicode)

    Returns:
        true of line is empty or only contains whitespace chars
    """
    if line == "":
        return True
    elif line.isspace():
        return True
    return False


def clean_cut(line: str, delimiters: list[str] | str, fields: str):
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
            parts = line.split(delimiter)
            if "-" in fields:
                start = fields.split("-")[0]
                stop = fields.split("-")[1]
                start = int(start) - 1 if start else 0
                stop = int(stop) if stop else len(parts)
                fields_slice = slice(start, stop)
            else:
                field = int(fields) - 1
                fields_slice = slice(field, field + 1)
            return True, delimiter.join(parts[fields_slice])
    return False, line


def clean_non_ascii(line: str):
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


def clean_lowercase(line: str):
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


def clean_title_case(line: str):
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


def clean_trim(line: str):
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
                cleaned_line = cleaned_line[len(x) :]
                has_match = True

            if cleaned_line.endswith(x):
                cleaned_line = cleaned_line[: -len(x)]
                has_match = True

        if has_match is False:
            break

    if line != cleaned_line:
        return True, cleaned_line
    else:
        return False, line


def clean_tab(line: bytes):
    """Replace tab character with ':' greedy

    Params:
        line (bytes)

    Returns:
        line (bytes)
    """
    if b"\x09" in line:
        line = sub(b"\x09+", b"\x3a", line)
        return True, line
    else:
        return False, line


def clean_hex(line: str):
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


def clean_html(line: str):
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


def clean_html_named(line: str):
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


def clean_newline(line: str):
    """Delete newline characters at start and end of line

    Params:
        line (Unicode)

    Returns:
        line (Unicode)
    """
    return_line = line.strip("\r\n")
    if return_line != line:
        return True, return_line
    else:
        return False, line


def check_controlchar(line: str):
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
        if category(c) in ["Cc", "Cf", "Cn", "Co", "Cs"]:
            return True, c
    return False, None


def check_regex(line: str, regexes: list[str]):
    """Checks if a line matches a list of regexes

    Params:
        line (unicode)
        regex (list)

    Returns:
        true if all regexes match
        false if line does not match regex
    """
    for regex in regexes:
        if search(regex, line):
            continue
        else:
            return False
    return True


def contains_at_least(line: str, bound: int, char_property: Callable[[str], bool]):
    """Check if the line contains at least `bound` characters with given property.

    Params:
        line (unicode)
        bound (int)
        char_property (str -> bool)

    Returns:
        true if at least `bound` characters match
        false otherwise
    """
    if bound == 0:
        return True

    count = 0
    for char in line:
        if char_property(char):
            count += 1
            if count >= bound:
                return True
    return False


def contains_at_most(line: str, bound: int, char_property: Callable[[str], bool]):
    """Check if the line contains at most `bound` characters with given property.

    Params:
        line (unicode)
        bound (int)
        char_property (str -> bool)

    Returns:
        true if at most `bound` characters match
        false otherwise
    """
    count = 0
    for char in line:
        if char_property(char):
            count += 1
            if count > bound:
                return False
    return True


def try_encoding(line: bytes, encoding: str):
    """Tries to decode a line using the supplied encoding

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

        # Define a set of control character categories to exclude
        excluded_controls = {"Cc", "Cf", "Cn", "Co", "Cs"}

        # Define a set of acceptable control characters
        acceptable_controls = {"\t", "\n", "\r", "\f", "\v"}

        # Check for invalid characters
        for c in line_decoded:
            if category(c) in excluded_controls and c not in acceptable_controls:
                return False
        return line_decoded
    except UnicodeDecodeError:
        return False


def clean_mojibake(line: str):
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


def clean_encode(line: bytes, input_encoding: list[str]):
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
    fallback_encodings = [
        "utf-8",
        "latin-1",
        "windows-1252",
        "ascii",
        "iso-8859-15",
        "macroman",
        "cp437",
        "iso-8859-2",
    ]
    line_decoded = False
    for encoding in input_encoding:
        line_decoded = try_encoding(line, encoding)
        if line_decoded is not False:
            break

    # All other methods failed, lets run the detect library on the line and try to guess the encoding.
    if line_decoded is False:
        encode = detect(line)
        if encode["encoding"]:
            try:
                line_decoded = line.decode(encode["encoding"])
            except (UnicodeDecodeError, LookupError) as _:  # noqa F841
                pass

    if line_decoded is False:
        # Lets try some fallback encodings
        for encoding in fallback_encodings:
            line_decoded = try_encoding(line, encoding)
            if line_decoded is not False:
                break

    if line_decoded is False:
        return False, "Unknown-detect"
    else:
        return True, line_decoded


def clean_up(lines: list[bytes], config: Config):
    """Main clean loop, this calls all the other clean functions.

    Args:
        line(bytes): Line to be cleaned up

    Returns:
        (str(Decoded line), str(Failed line))
    """
    results: list[str] = []
    log: list[str] = []

    for line in lines:
        # Check if the limit is set, if so minus 1 and if 0 is reached lets quit.
        if type(config["limit"]) is int:
            if config["limit"] > 0:
                config["limit"] -= 1
            else:
                break

        # When stop is set all demeuking module will be skipped for this line.
        if config["debug"]:
            log.append(f"----BEGIN---- {hexlify(line)}{linesep}")
        # Replace tab chars as ':' greedy
        if config["tab"]:
            status, line = clean_tab(line)
            if status and config["debug"]:
                log.append(f"Clean_tab; replaced tab characters; {line}{linesep}")

        line_decoded = None

        # Converting enoding to UTF-8
        if config["encode"]:
            status, line_decoded = clean_encode(line, config["input_encoding"])
            if status is False:
                log.append(f"Clean_encode; decoding error with {line_decoded}; {line}{linesep}")
                continue  # stop
            elif status is True and config["debug"]:
                log.append(f"Clean_encode; decoded line; {line_decoded}{linesep}")
        else:
            try:
                line_decoded = line.decode(config["input_encoding"][0])
                if config["debug"]:
                    log.append(f"Clean_up; decoded using input_encoding option; {line_decoded}{linesep}")
            except UnicodeDecodeError as _:  # noqa F841
                log.append(f"Clean_up; decoding error with unknown; {line}{linesep}")
                continue  # stop

        # From here it is expected that line is correctly decoded!
        # Check if some lines contain a hex string like $HEX[41424344]
        if config["hex"]:
            status, hex_line_decoded = clean_hex(line_decoded)
            if status and isinstance(hex_line_decoded, bytes):  # Should be bytes always
                # Lines contains hex, this function will return binary string, so add it back to
                # our undecoded lines
                lines.append(hex_line_decoded)
                if config["debug"]:
                    log.append(f"Clean_hex; replaced $HEX[], added to queue and quiting; {line}{linesep}")
                # Aborting future processing of this line.
                continue

        # Check if there are html char in the line, decode them if there are
        if config["html"]:
            status, html_line_decoded = clean_html(line_decoded)
            if status:
                # Line contains html string, because this can be binary data (linefeeds etc)
                # convert back to binary string and add to queue again.
                lines.append(html_line_decoded.encode())
                if config["debug"]:
                    log.append(f"Clean_html; replaced html, added to queue and quiting; {line_decoded}{linesep}")
                continue

        # Checks if there are any mojibakes inside the line
        # You must mojibake before removing control chars! Some control chars
        # are part of a valid mojibake.
        if config["mojibake"]:
            status, line_decoded = clean_mojibake(line_decoded)
            if status and config["debug"]:
                log.append(f"Clean_mojibake; found a mojibake; {line}{linesep}")

        # Delete leading and trailing newline characters
        if config["newline"]:
            status, line_decoded = clean_newline(line_decoded)
            if status and config["debug"]:
                log.append(f"Clean_newline; deleted newline characters; {line_decoded!r}{linesep}")

        # Checks if there are any control chars inside line
        if config["check_controlchar"]:
            status, cc = check_controlchar(line_decoded)
            if status:
                # Control char detected
                log.append(f"Check_controlchar; found controlchar {cc!r}; {line_decoded!r}{linesep}")
                continue

        # Check if there are named html chars in the line
        if config["html_named"]:
            status, line_decoded = clean_html_named(line_decoded)
            if status and config["debug"]:
                log.append(f"Clean_html_named; found named html character; {line_decoded}{linesep}")

        # Delete leading and trailing character sequences representing a newline
        if config["trim"]:
            status, line_decoded = clean_trim(line_decoded)
            if status and config["debug"]:
                log.append(f"Clean_trim; found trim sequence; {line_decoded!r}{linesep}")

        # Should we do the cut?
        if config["cut"]:
            status, line_decoded = clean_cut(line_decoded, config["delimiter"], config["cut_fields"])
            if status and config["debug"]:
                log.append(f"Clean_cut; field cutted; {line_decoded}{linesep}")

        # Replace umlauts
        if config["umlaut"]:
            status, line_decoded = clean_add_umlaut(line_decoded)
            if status and config["debug"]:
                log.append(f"Clean_umlaut; umlaut replaced; {line_decoded}{linesep}")

        # Replace non-ascii
        if config["non_ascii"]:
            status, line_decoded = clean_non_ascii(line_decoded)
            if status and config["debug"]:
                log.append(f"Clean_non_ascii; non-ascii replaced; {line_decoded}{linesep}")

        # Replace all letters with lowercase
        if config["lowercase"]:
            status, line_decoded = clean_lowercase(line_decoded)
            if status and config["verbose"]:
                log.append(f"Clean_lowercase; all capitals replaced; {line_decoded}{linesep}")

        # Replace first letter of a word to a uppercase letter
        if config["title_case"]:
            status, line_decoded = clean_title_case(line_decoded)
            if status and config["debug"]:
                log.append(f"Clean_title_case; non-ascii replaced; {line_decoded}{linesep}")

        # Should we remove emails?
        if config["remove_email"]:
            status, line_decoded = remove_email(line_decoded)
            if status and config["debug"]:
                log.append(f"Remove_email; email found; {line_decoded}{linesep}")

        if config["googlengram"]:
            status, line_decoded = clean_googlengram(line_decoded)
            if status and config["debug"]:
                log.append(f"Clean_googlengram; tos found and removed; {line_decoded}{linesep}")

        if config["check_case"]:
            status, c = check_case(line_decoded)
            if not status:
                log.append(f"Check_case; dropped line because of {c}; {line_decoded}{linesep}")
                continue

        if config["check_length"]:
            if not check_length(line_decoded, min=config["check_min_length"], max=config["check_max_length"]):
                log.append(f"Check_length; dropped line because of failed length check; {line_decoded}{linesep}")
                continue

        if config["check_email"]:
            if not check_email(line_decoded):
                log.append(f"Check_email; dropped line because found email; {line_decoded}{linesep}")
                continue

        if config["check_hash"]:
            if not check_hash(line_decoded):
                log.append(f"Check_hash; dropped line because found a hash; {line_decoded}{linesep}")
                continue

        if config["check_mac_address"]:
            if not check_mac_address(line_decoded):
                log.append(f"Check_mac_address; dropped line because found a MAC address; {line_decoded}{linesep}")
                continue

        if config["check_non_ascii"]:
            if not check_non_ascii(line_decoded):
                log.append(f"Check_non_ascii; dropped line because non ascii char found; {line_decoded}{linesep}")
                continue

        if config["check_replacement_character"]:
            if check_character(line_decoded, "�"):
                log.append(f'Check_replacement_character; dropped line because "�" found; {line_decoded}{linesep}')
                continue

        if config["check_regex"]:
            if not check_regex(line_decoded, config["check_regex"]):
                log.append(f"Check_regex; dropped line because it does not match the regex; {line_decoded}{linesep}")
                continue

        if config["check_min_digits"] > 0:
            if not contains_at_least(line_decoded, config["check_min_digits"], str.isdigit):
                log.append(
                    f"Check_min_digits; dropped line because it contains less than "
                    f"{config['check_min_digits']} digits; {line_decoded}{linesep}"
                )
                continue


        if config["check_max_digits"] != float("inf"):
            max_digits = int(config["check_max_digits"])
            if not contains_at_most(line_decoded, max_digits, str.isdigit):
                log.append(
                    f"Check_max_digits; dropped line because it contains more than "
                    f"{config['check_max_digits']} digits; {line_decoded}{linesep}"
                )
                continue

        if config["check_min_uppercase"] > 0:
            if not contains_at_least(line_decoded, config["check_min_uppercase"], str.isupper):
                log.append(
                    f"Check_min_lowercase; dropped line because it contains less than "
                    f"{config['check_min_uppercase']} lowercase characters; {line_decoded}{linesep}"
                )
                continue

        if config["check_max_uppercase"] != float("inf"):
            max_uppercase = int(config["check_max_uppercase"])
            if not contains_at_most(line_decoded, max_uppercase, str.isupper):
                log.append(
                    f"Check_max_uppercase; dropped line because it contains more than "
                    f"{max_uppercase} uppercase characters; {line_decoded}{linesep}"
                )
                continue

        if config["check_min_specials"] > 0:
            if not contains_at_least(
                line_decoded, config["check_min_specials"], lambda char: not char.isalnum() and not char.isspace()
            ):
                log.append(
                    f"Check_min_specials; dropped line because it contains less than "
                    f"{config['check_min_specials']} special characters; {line_decoded}{linesep}"
                )
                continue

        if config["check_max_specials"] != float("inf"):
            max_specials = int(config["check_max_specials"])
            if not contains_at_most(line_decoded, max_specials, lambda char: not char.isalnum() and not char.isspace()):
                log.append(
                    f"Check_max_specials; dropped line because it contains more than "
                    f"{max_specials} special characters; {line_decoded}{linesep}"
                )
                continue

        if config["check_starting_with"]:
            to_check = config["check_starting_with"]

            if check_starting_with(line_decoded, to_check):
                log.append(f"Check_starting_with; dropped line because {to_check} found; {line_decoded}{linesep}")
                continue

        if config["check_uuid"]:
            if not check_uuid(line_decoded):
                log.append(f"Check_uuid; dropped line because found a uuid; {line_decoded}{linesep}")
                continue

        if config["check_ending_with"]:
            to_check = config["check_ending_with"]
            if check_ending_with(line_decoded, to_check):
                log.append(f"Check_ending_with; dropped line because {to_check} found; {line_decoded}{linesep}")
                continue

        if config["check_empty_line"]:
            if check_empty_line(line_decoded):
                log_line = "Check_empty_line; dropped line because is empty or only contains whitespace;"
                log.append(f"{log_line} {line_decoded}{linesep}")
                continue

        if config["remove_punctuation"]:
            status, line_decoded = remove_punctuation(line_decoded, config["punctuation"])
            if status and config["debug"]:
                log.append(f"Remove_punctuation; stripped punctuation; {line_decoded}{linesep}")

        if config["remove_strip_punctuation"]:
            status, line_decoded = remove_strip_punctuation(line_decoded, config["punctuation"])
            if status and config["debug"]:
                log.append(f"Remove_strip_punctuation; stripped punctuation; {line_decoded}{linesep}")

        # Some clean modules will modify the end result, those modification will be added here.
        # They will be added to the running thread, this might cause one thread to have more work
        # then others.
        if config["add_split"]:
            modified_lines = add_split(line_decoded)
            if modified_lines:
                for modified_line in modified_lines:
                    if config["debug"]:
                        log.append(f"Add_split; new line because of split; {modified_line}{linesep}")
                    lines.append(modified_line.encode())

        if config["add_lower"]:
            modified_line = add_lower(line_decoded)
            if modified_line:
                if config["debug"]:
                    log.append(f"Add_lower; new line; {modified_line}{linesep}")
                lines.append(modified_line.encode())

        if config["add_latin_ligatures"]:
            modified_line = add_latin_ligatures(line_decoded)
            if modified_line:
                if config["debug"]:
                    log.append(f"Add_latin_ligatures; new line; {modified_line}{linesep}")
                lines.append(modified_line.encode())

        if config["add_umlaut"]:
            status, modified_line = clean_add_umlaut(line_decoded)
            if status:
                if config["debug"]:
                    log.append(f"Add_umlaut; new line; {modified_line}{linesep}")
                lines.append(modified_line.encode())

        if config["add_without_punctuation"]:
            modified_line = add_without_punctuation(line_decoded, config["punctuation"])
            if modified_line:
                if config["debug"]:
                    log.append(f"Add_without_punctuation; new line; {modified_line}{linesep}")
                lines.append(modified_line.encode())

        if config["debug"]:
            log.append(f"----End---- {line_decoded}{linesep}{linesep}")
        results.append(f"{line_decoded}{linesep}")

    return {"results": results, "log": log}


def chunkify(filename: str | BinaryIO, config: Config, size: int = CHUNK_SIZE):
    if isinstance(filename, str):
        with open(filename, "rb") as fh:
            for _ in range(0, config["skip"]):
                fh.readline()

            while True:
                lines = [line.rstrip(b"\n") for line in fh.readlines(size)]
                yield lines
                if len(lines) == 0:
                    break
    else:
        for _ in range(0, config["skip"]):
            filename.readline()

        while True:
            lines = [line.rstrip(b"\n") for line in filename.readlines(size)]
            yield lines
            if len(lines) == 0:
                break


# Quick to default logging to stderr instead
def stderr_print(config: Config, *args, **kwargs):
    if config["verbose"] is True:
        kwargs.setdefault("file", stderr)
        print(*args, **kwargs)


def parse_arguments():
    parser = argparse.ArgumentParser(description="Description of your program")
    parser.add_argument("--version", action="store_true", help="Show version and exit")
    parser.add_argument("-i", "--input", type=str, help="Input file")
    parser.add_argument("-o", "--output", type=str, help="Output file")
    parser.add_argument("-l", "--log", type=str, help="Log file")
    parser.add_argument("-j", "--threads", type=str, help="Number of threads to use")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--progress", action="store_true", help="Show progress")
    # parser.add_argument('--force', action='store_true', help='Force mode')
    parser.add_argument("-n", "--limit", type=int, help="Limit the number of lines to process")
    parser.add_argument("-s", "--skip", type=int, help="Skip the first N lines")
    parser.add_argument("--input-encoding", type=str, help="Input encoding")
    parser.add_argument("--output-encoding", type=str, help="Output encoding")
    parser.add_argument("--punctuation", type=str, help="Punctuation to remove")
    parser.add_argument("-c", "--cut", action="store_true", help="Enable cut mode")
    parser.add_argument("-d", "--delimiter", type=str, help="Delimiter to use")
    parser.add_argument("--cut-before", action="store_true", help="Cut fields before specified field")
    parser.add_argument("-f", "--cut-fields", type=str, help="Fields to cut")
    parser.add_argument("--hex", action="store_true", help="Enable hex mode")
    parser.add_argument("--html", action="store_true", help="Enable HTML mode")
    parser.add_argument("--html-named", action="store_true", help="Enable named HTML mode")
    parser.add_argument("--umlaut", action="store_true", help="Enable umlaut mode")
    parser.add_argument("--non-ascii", action="store_true", help="Enable non-ASCII mode")
    parser.add_argument("--lowercase", action="store_true", help="Convert to lowercase")
    parser.add_argument("--title-case", action="store_true", help="Convert to title case")
    parser.add_argument("--mojibake", action="store_true", help="Enable mojibake mode")
    parser.add_argument("--encode", action="store_true", help="Enable encode mode")
    parser.add_argument("--tab", action="store_true", help="Enable tab mode")
    parser.add_argument("--newline", action="store_true", help="Enable newline mode")
    parser.add_argument("--trim", action="store_true", help="Enable trim mode")
    parser.add_argument("--check-min-length", type=int, help="Check minimum length")
    parser.add_argument("--check-max-length", type=int, help="Check maximum length")
    parser.add_argument("--check-case", action="store_true", help="Check case")
    parser.add_argument("--check-email", action="store_true", help="Check email")
    parser.add_argument("--check-hash", action="store_true", help="Check hash")
    parser.add_argument("--check-mac-address", action="store_true", help="Check MAC address")
    parser.add_argument("--check-non-ascii", action="store_true", help="Check non-ASCII characters")
    parser.add_argument("--check-replacement-character", action="store_true", help="Check replacement character")
    parser.add_argument("--check-starting-with", type=str, help="Check starting with")
    parser.add_argument("--check-uuid", action="store_true", help="Check UUID")
    parser.add_argument("--check-ending-with", type=str, help="Check ending with")
    parser.add_argument("--check-empty-line", action="store_true", help="Check empty line")
    parser.add_argument("--check-controlchar", action="store_true", help="Check control characters")
    parser.add_argument("--check-regex", type=str, help="Check regex")
    parser.add_argument("--check-min-digits", type=int, help="Check minimum digits")
    parser.add_argument("--check-max-digits", type=int, help="Check maximum digits")
    parser.add_argument("--check-min-uppercase", type=int, help="Check minimum uppercase")
    parser.add_argument("--check-max-uppercase", type=int, help="Check maximum uppercase")
    parser.add_argument("--check-min-specials", type=int, help="Check minimum special characters")
    parser.add_argument("--check-max-specials", type=int, help="Check maximum special characters")
    parser.add_argument("--add-lower", action="store_true", help="Add lowercase")
    parser.add_argument("--add-latin-ligatures", action="store_true", help="Add Latin ligatures")
    parser.add_argument("--add-split", action="store_true", help="Add split")
    parser.add_argument("--add-umlaut", action="store_true", help="Add umlaut")
    parser.add_argument("--add-without-punctuation", action="store_true", help="Add without punctuation")
    parser.add_argument("--remove-strip-punctuation", action="store_true", help="Remove strip punctuation")
    parser.add_argument("--remove-punctuation", action="store_true", help="Remove punctuation")
    parser.add_argument("--remove-email", action="store_true", help="Remove email")
    parser.add_argument("-g", "--googlengram", action="store_true", help="Enable Google Ngram mode")
    parser.add_argument("--leak", action="store_true", help="Enable leak mode")
    parser.add_argument("--leak-full", action="store_true", help="Enable full leak mode")

    return parser.parse_args()


def main():
    args = parse_arguments()

    if args.version:
        print(f"demeuk - {version}")
        exit()

    if args.threads:
        if args.threads == "all":
            threads = cpu_count()
        else:
            threads = int(args.threads)
    else:
        threads = cpu_count()

    # Lets create the default config
    # global config
    config: Config = {
        "input_encoding": ["utf-8"],
        "output_encoding": "utf-8",
        "cut": False,
        "delimiter": ":",
        "cut_fields": "2-",
        "verbose": False,
        "debug": False,
        "progress": False,
        "limit": False,
        "skip": False,
        # Modify
        "encode": False,
        "mojibake": False,
        "tab": False,
        "trim": False,
        "newline": False,
        "hex": False,
        "html": False,
        "html_named": False,
        "umlaut": False,
        "non_ascii": False,
        "title_case": False,
        "lowercase": False,
        # Check
        "check_length": False,
        "check_min_length": 0,
        "check_max_length": 0,
        "check_controlchar": False,
        "check_case": False,
        "check_email": False,
        "check_hash": False,
        "check_mac_address": False,
        "check_non_ascii": False,
        "check_replacement_character": False,
        "check_starting_with": False,
        "check_uuid": False,
        "check_ending_with": False,
        "check_empty_line": False,
        "check_regex": False,
        "check_min_digits": 0,
        "check_max_digits": float("inf"),
        "check_min_uppercase": 0,
        "check_max_uppercase": float("inf"),
        "check_min_specials": 0,
        "check_max_specials": float("inf"),
        # Add
        "add_lower": False,
        "add_latin_ligatures": False,
        "add_split": False,
        "add_umlaut": False,
        "add_without_punctuation": False,
        # Remove
        "remove_strip_punctuation": False,
        "remove_punctuation": False,
        "remove_email": False,
        "punctuation": string_punctuation + " ",
        # Groups
        "googlengram": False,
        "leak": False,
        "leak_full": False,
    }

    # Lets update the config with the arguments
    config["verbose"] = args.verbose
    config["debug"] = args.debug
    config["progress"] = args.progress

    if args.progress and (config["verbose"] or config["debug"]):
        stderr_print(config, "Progress can not be used with verbose or debug")
        exit(2)

    # config["force"] = args.force

    config["limit"] = args.limit if args.limit else False
    config["skip"] = args.skip if args.skip else False
    config["input_encoding"] = args.input_encoding.split(",") if args.input_encoding else config["input_encoding"]
    config["output_encoding"] = args.output_encoding if args.output_encoding else config["output_encoding"]
    config["punctuation"] = args.punctuation if args.punctuation else config["punctuation"]
    config["cut"] = args.cut

    if args.delimiter:
        splitter = ","
        if len(args.delimiter) >= 1:
            if args.delimiter[0] == ",":
                splitter = ";"
        config["delimiter"] = args.delimiter.split(splitter)

    if args.cut_before and not args.cut_fields:
        config["cut_fields"] = "-1"
    elif args.cut_fields:
        config["cut_fields"] = args.cut_fields

    config["hex"] = args.hex
    config["html"] = args.html
    config["html_named"] = args.html_named
    config["umlaut"] = args.umlaut
    config["non_ascii"] = args.non_ascii
    config["lowercase"] = args.lowercase
    config["title_case"] = args.title_case
    config["mojibake"] = args.mojibake
    config["encode"] = args.encode
    config["tab"] = args.tab
    config["newline"] = args.newline
    config["trim"] = args.trim

    if args.check_min_length:
        config["check_length"] = True
        config["check_min_length"] = args.check_min_length

    if args.check_max_length:
        config["check_length"] = True
        config["check_max_length"] = args.check_max_length

    config["check_case"] = args.check_case
    config["check_email"] = args.check_email
    config["check_hash"] = args.check_hash
    config["check_mac_address"] = args.check_mac_address
    config["check_non_ascii"] = args.check_non_ascii
    config["check_replacement_character"] = args.check_replacement_character
    config["check_uuid"] = args.check_uuid
    config["check_empty_line"] = args.check_empty_line
    config["check_controlchar"] = args.check_controlchar
    config["check_starting_with"] = args.check_starting_with.split(",") if args.check_starting_with else False
    config["check_ending_with"] = args.check_ending_with.split(",") if args.check_ending_with else False
    config["check_regex"] = args.check_regex.split(",") if args.check_regex else False

    config["check_min_digits"] = args.check_min_digits if args.check_min_digits != None else config["check_min_digits"]
    config["check_max_digits"] = args.check_max_digits if args.check_max_digits != None else config["check_max_digits"]
    config["check_min_uppercase"] = args.check_min_uppercase if args.check_min_uppercase != None else config["check_min_uppercase"]
    config["check_max_uppercase"] = args.check_max_uppercase if args.check_max_uppercase != None else config["check_max_uppercase"]
    config["check_min_specials"] = args.check_min_specials if args.check_min_specials != None else config["check_min_specials"]
    config["check_max_specials"] = args.check_max_specials if args.check_max_specials != None else config["check_max_specials"]

    config["add_lower"] = args.add_lower
    config["add_latin_ligatures"] = args.add_latin_ligatures
    config["add_split"] = args.add_split
    config["add_umlaut"] = args.add_umlaut
    config["add_without_punctuation"] = args.add_without_punctuation

    config["remove_strip_punctuation"] = args.remove_strip_punctuation
    config["remove_punctuation"] = args.remove_punctuation
    config["remove_email"] = args.remove_email

    config["googlengram"] = args.googlengram
    config["leak"] = args.leak
    config["leak_full"] = args.leak_full

    if args.googlengram:
        config["cut"] = False
        config["remove_email"] = False
        config["encode"] = True
        config["mojibake"] = False
        config["check_controlchar"] = False
        config["tab"] = False
        config["googlengram"] = True

    if args.leak:
        config["mojibake"] = True
        config["encode"] = True
        config["newline"] = True
        config["check_controlchar"] = True

    if args.leak_full:
        config["mojibake"] = False
        config["encode"] = True
        config["newline"] = True
        config["check_controlchar"] = True
        config["hex"] = True
        config["html"] = True
        config["html_named"] = True
        config["check_hash"] = True
        config["check_mac_address"] = True
        config["check_uuid"] = True
        config["check_email"] = True
        config["check_replacement_character"] = True
        config["check_empty_line"] = True

    input_files_data: list[InputFileData] = []
    if args.input:
        stderr_print(config, f"Main: input found in {args.input}")
        input_files = tqdm(
            glob(args.input, recursive=True),
            desc="Files processed",
            mininterval=0.1,
            unit=" files",
            disable=not config["progress"],
            position=0,
        )

        if not access(os.path.dirname(args.input), R_OK):
            stderr_print(config, f"Cannot read input file from {args.input}")
            exit(1)

        for input_file in input_files:
            if not access(input_file, R_OK):
                stderr_print(config, f"Cannot read input file from {input_file}")
                exit(1)

            chunk_estimation = int(ceil(path.getsize(input_file) / CHUNK_SIZE))

            input_files_data.append({"filename": input_file, "chunk_estimation": chunk_estimation})
    else:
        stderr_print(config, "Main: no input file found using stdin")

        data = stdin.buffer.read()
        buffer = BytesIO(data)

        chunk_estimation = int(ceil(len(data) / CHUNK_SIZE))

        buffer.seek(0)
        input_files_data.append({"filename": buffer, "chunk_estimation": chunk_estimation})

    if args.output and not access(path.dirname(args.output), W_OK):
        stderr_print(config, f"Cannot write output file to {args.output}")
        exit(1)

    if args.log and not (access(args.log, F_OK) or access(path.dirname(args.log), W_OK)):
        stderr_print(config, f"Cannot write log file to {args.log}")
        exit(1)

    stderr_print(config, f"Main: running demeuk - {version}")
    stderr_print(config, f"Main: Using {threads} core(s) of total available cores: {cpu_count()}")
    stderr_print(config, f"Main: start chunking file {args.input}")

    if args.output:
        stderr_print(config, f"Main: output found in {args.output}")
        output_file = open(args.output, "w", encoding=config["output_encoding"])
    else:
        output_file = stdout

    if args.log:
        stderr_print(config, f"Main: logs found in {args.log}")
        log_file = open(args.log, "a", encoding="utf-8")
    else:
        log_file = stderr

    stderr_print(config, "Main: processing started.")

    def write_results(results: list[str]):
        output_file.writelines(results)
        output_file.flush()

    def write_log(log: str):
        if config["debug"] or config["verbose"] or log_file:
            log_file.writelines(log)
            log_file.flush()

    def write_results_and_log(async_result: dict[str, Any]):
        write_results(async_result["results"])
        write_log(async_result["log"])

    write_log(f"Running demeuk - {version}{linesep}")

    with Manager() as manager:
        task_queue = manager.Queue(threads)
        processes: list[Process] = []

        def worker():
            while True:
                try:
                    chunk = task_queue.get(timeout=1)
                except Exception:
                    continue

                if chunk is None:
                    break

                try:
                    result = clean_up(chunk, config)
                    write_results_and_log(result)
                finally:
                    task_queue.task_done()

        for _ in range(threads):
            process = Process(target=worker)
            process.start()
            processes.append(process)

        for input_file_data in input_files_data:
            for chunk in tqdm(
                chunkify(input_file_data["filename"], config, CHUNK_SIZE),
                mininterval=1,
                unit=" chunks",
                disable=not config["progress"],
                total=input_file_data["chunk_estimation"],
                position=1,
            ):
                task_queue.put(chunk)

        stderr_print(config, "Main: done submitting all jobs, waiting for threads to finish")

        for _ in processes:
            task_queue.put(None)

        for process in processes:
            process.join()

        stderr_print(config, "Main: all done")

    if output_file is not stdout:
        output_file.close()

    if log_file is not stderr:
        log_file.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted by user")
        exit(3)
