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
        -l --log <path to file>         Optional, specify where the log file needs to be written to (default: stderr)
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
                                        with as comma-separated list.
        --check-ending-with <string>    Drop lines ending with string, can be multiple strings. Specify multiple
                                        with as comma-separated list.
        --check-contains <string>       Drop lines containing string, can be multiple strings. Specify multiple
                                        with as comma-separated list.
        --check-empty-line              Drop lines that are empty or only contain whitespace characters
        --check-regex <string>          Drop lines that do not match the regex. Regex is a comma separated list of
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
        --add-first-upper               If a line does not contain a capital letter this will add the capital variant
        --add-title-case                Add a line like 'this test string' also as a 'This Test String'
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
import os
import select
import sys
from binascii import hexlify, unhexlify
from collections.abc import Callable
from glob import glob
from html import unescape
from math import ceil
from multiprocessing import Manager, Process, cpu_count
from os import F_OK, R_OK, W_OK, access, linesep, path
from re import Match
from re import compile as re_compile
from re import search
from re import split as re_split
from re import sub
from string import punctuation as string_punctuation
from typing import BinaryIO, TypedDict
from unicodedata import category

from chardet import detect
from ftfy import fix_encoding
from ftfy.chardata import HTML_ENTITIES, HTML_ENTITY_RE
from ftfy.fixes import fix_latin_ligatures
from nltk import str2tuple  # type: ignore
from nltk.tokenize import WhitespaceTokenizer
from tqdm import tqdm
from unidecode import unidecode

VERSION = "4.5.1"

# Search from start to finish for the string $HEX[], with block of a-f0-9 with even number
# of hex chars. The first match group is repeated.
HEX_REGEX = re_compile(r"^\$(?:HEX|hex)\[((?:[0-9a-fA-F]{2})+)\]$")
EMAIL_ALLOWED_CHARS = r"a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-"
EMAIL_REGEX = (
    rf"[a-zA-Z0-9][{EMAIL_ALLOWED_CHARS}]{{0,63}}@[a-zA-Z0-9](?:[a-zA-Z0-9-]{{0,61}}[a-zA-Z0-9])?(?:\.[a-zA-Z]{{2,6}})+"
)
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


class InputFileData(TypedDict):
    file: str | BinaryIO
    chunk_estimation: int | None


class Config(TypedDict):
    """Configuration for the demeuk tool"""

    input_file: str
    output_file: str
    log: str
    threads: int
    input_encoding: list[str]
    output_encoding: str
    cut: bool
    cut_fields: str
    cut_before: bool
    verbose: bool
    debug: bool
    progress: bool
    limit: int | bool
    skip: int | bool
    decode: bool
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
    check_min_length: int
    check_max_length: int
    check_controlchar: bool
    check_case: bool
    check_email: bool
    check_hash: bool
    check_mac_address: bool
    check_non_ascii: bool
    check_replacement_character: bool
    check_starting_with: list[str]
    check_contains: list[str]
    check_uuid: bool
    check_ending_with: list[str]
    check_empty_line: bool
    check_regex: list[str]
    check_min_digits: int
    check_max_digits: int | float
    check_min_uppercase: int
    check_max_uppercase: int | float
    check_min_specials: int
    check_max_specials: int | float
    check_min_length: int
    check_max_length: int
    check_length: bool
    add_lower: bool
    add_latin_ligatures: bool
    add_split: bool
    add_umlaut: bool
    add_without_punctuation: bool
    add_first_upper: bool
    add_title_case: bool
    remove_strip_punctuation: bool
    remove_punctuation: bool
    remove_email: bool
    googlengram: bool
    leak: bool
    leak_full: bool

    punctuation: str
    delimiter: list[str]


def _unescape_fixup_named(match: Match[str]):
    """
    Replace one matched HTML entity with the character it represents,
    if possible.

    Based on: ftfy.fixes._unescape_fixup
    """
    text = match.group(0)
    if text in HTML_ENTITIES:
        return HTML_ENTITIES[text]
    return text


def _unescape_fixup(match: Match[str]):
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

        return unescaped

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
    words = WhitespaceTokenizer().tokenize(return_line)  # type: ignore

    for word in words:  # type: ignore
        # in >1-grams transitions to specific tags are written as:
        # The_ADJ _NOUN_ (meaning from The there is a transition to a noun
        # We remove those
        if word[0] != "_" and word[-1] != "_":
            # Split the token and the tag based on the '_'
            token, tag = str2tuple(word, "_")  # type: ignore
            # Punct will be added using rules.

            if len(token) > 1:
                if tag not in {"PUNCT", ".", ""}:
                    clean.append(token)
            elif token not in string_punctuation:
                clean.append(token)
    return_line = " ".join(clean)
    if return_line != line:
        return True, return_line

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

    return None


def add_first_upper(line: str):
    """Returns the line with the first letter capitalized and all the others in lowercase.

    Param:
        line (unicode)

    Returns:
        False if they are the same
        Capitalized string if they are not
    """
    line_first_upper = line.capitalize()
    if line != line_first_upper:
        return line_first_upper

    return None


def add_title_case(line: str):
    """Returns title case string where all the first letters are capitals and all others in lowercase.

    Param:
        line (unicode)

    Returns:
        False if they are the same
        Title string if they are not
    """
    line_title_case = line.title()
    if line != line_title_case:
        return line_title_case

    return None


def add_latin_ligatures(line: str):
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

    return None


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

    return None


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

    return False, line


def add_split(line: str, punctuation: tuple[str, ...] = (" ", "-", r"\.")) -> list[str]:
    """Split the line on the punctuation and return elements longer then 1 char.

    Param:
        line (unicode)

    Returns:
        split line
    """
    for p in punctuation:
        if p in line:
            return [i for i in re_split("|".join(punctuation), line) if len(i) > 1]
    return []


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

            return False, c
    return True, None


def check_length(line: str, min_length: int = 0, max_length: int = 0):
    """Does a length check on the line

    Params:
        line (unicode)
        min (int)
        max (int)

    Returns:
        true if length is ok
    """
    status = True
    if min_length and status:
        status = len(line) >= min_length
    if max_length and status:
        status = len(line) < max_length
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


def check_contains(line: str, strings: list[str]):
    """Checks if a line does not contain specific strings

    Params:
        line (unicode)
        strings[str]

    Returns:
        true if line does contain any one of the strings

    """
    for string in strings:
        if string in line:
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

    if line.isspace():
        return True

    return False


def clean_cut(line: str, delimiters: list[str], fields: str):
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

    return False, line


def clean_tab_str(line: str):
    """Replace tab character with ':' greedy

    Params:
        line (bytes)

    Returns:
        line (bytes)
    """
    if "\t" in line:
        line = sub("\t+", ":", line)
        return True, line

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


def contains_at_most(line: str, bound: int | float, char_property: Callable[[str], bool]):
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
    """Tries to decode a line using supplied encoding

    Params:
        line (Byte): byte variable that will be decoded
        encoding (string): the encoding to be tried

    Returns:
        False if decoding failed
        String if decoding worked
    """

    # Define a set of control character categories to exclude
    excluded_controls = {"Cc", "Cf", "Cn", "Co", "Cs"}

    # Define a set of acceptable control characters
    acceptable_controls = {"\t", "\n", "\r", "\f", "\v"}

    try:
        # Try to decode the line
        line_decoded = line.decode(encoding)
        # Some encoding will decoded almost any line, lets check if we have invalid chars.
        # If we have invalid chars (except for tab like chars) we will fail
        for c in line_decoded:
            # Check if the character is a control character
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
        found_encoding = encode.get("encoding")
        if found_encoding:
            try:
                line_decoded = line.decode(found_encoding)
            except (UnicodeDecodeError, LookupError):  # noqa F841
                pass

    if line_decoded is False:
        # Lets try some fallback encodings
        for encoding in fallback_encodings:
            line_decoded = try_encoding(line, encoding)
            if line_decoded is not False:
                break

    if line_decoded is False:
        return False, "Unknown-detect"

    return True, line_decoded


def clean_up(config: Config, original_lines: list[bytes]):  # pylint: disable=R0912:too-many-branches
    """Main clean loop, this calls all the other clean functions.

    Args:
        line(bytes): Line to be cleaned up

    Returns:
        (str(Decoded line), str(Failed line))
    """
    results: list[str] = []
    log: list[str] = []
    lines: list[str] = []

    def add_to_lines(line: str | bytes | None, status: bool = True):
        if line is None:
            return

        if isinstance(line, bytes):
            new_line = preprocess_line(line)
            if new_line is None:
                return

            add_to_lines(new_line, status)
            return

        if status and line not in lines:
            lines.append(line)

    def add_to_log(
        message: str,
        status: bool = True,
        require_debug: bool = True,
        require_verbose: bool = False,
        no_status_message: str | None = None,
    ):
        if status:
            if require_verbose and not config["verbose"] and not config["debug"]:
                # If verbose required and verbose and debug are not set, return
                return

            if require_debug and not require_verbose and not config["debug"]:
                # If debug required and debug is not set and verbose is not required, return
                return

            log.append(message)
        elif no_status_message:
            log.append(no_status_message)

    def preprocess_line(line: bytes) -> str | None:
        add_to_log(f"----BEGIN DECODING---- {hexlify(line)}{linesep}")
        # Replace tab chars as ':' greedy
        if config["tab"]:
            status, line = clean_tab(line)
            add_to_log(f"Clean_tab; replaced tab characters; {line}{linesep}", status)

        if config["decode"]:
            status, line_decoded = clean_encode(line, config["input_encoding"])

            add_to_log(
                f"Clean_encode; decoded line; {line_decoded}{linesep}",
                status,
                no_status_message=f"Clean_encode; decoding error with {line_decoded}; {line}{linesep}",
            )

            if not status:
                return None
        else:
            try:
                line_decoded = line.decode(config["input_encoding"][0])
                add_to_log(f"Clean_up; decoded using input_encoding option; {line_decoded}{linesep}")
            except UnicodeDecodeError:  # noqa F841
                log.append(f"Clean_up; decoding error with unknown; {line}{linesep}")
                return None

        # From here it is expected that line is correctly decoded!
        # Check if some lines contain a hex string like $HEX[41424344]
        if config["hex"]:
            status, line_decoded = clean_hex(line_decoded)

            add_to_log(f"Clean_hex; replaced $HEX[]; added to queue and quiting {line}{linesep}", status)

            if isinstance(line_decoded, bytes):
                return preprocess_line(line_decoded)

        add_to_log(f"----END DECODING---- {line_decoded}{linesep}")

        return line_decoded

    for line in original_lines:
        add_to_lines(line)

    for line_decoded in lines:
        # Check if the limit is set, if so minus 1 and if 0 is reached lets quit.
        if not isinstance(config["limit"], bool):
            if config["limit"] > 0:
                config["limit"] -= 1
            else:
                break

        # When stop is set all demeuking module will be skipped for this line.
        add_to_log(f"----BEGIN LINE---- {line_decoded}{linesep}")

        # Replace tab chars as ':' greedy
        if config["tab"]:
            status, line_decoded = clean_tab_str(line_decoded)
            add_to_log(f"Clean_tab; replaced tab characters; {line_decoded}{linesep}", status)

        # From here it is expected that line is correctly decoded!
        # Check if some lines contain a hex string like $HEX[41424344]
        if config["hex"]:
            status, line_decoded = clean_hex(line_decoded)

            add_to_log(
                f"Clean_hex; replaced $HEX[]; added to queue and quiting {line_decoded}{linesep}",
                status,
            )
            add_to_lines(line_decoded, status)

            if isinstance(line_decoded, bytes):
                continue

        # Check if there are html char in the line, decode them if there are
        if config["html"]:
            status, line_decoded = clean_html(line_decoded)

            add_to_log(
                f"Clean_html; replaced html, added to queue and quiting; {line_decoded}{linesep}",
                status,
            )
            add_to_lines(line_decoded, status)

            if status:
                continue

        # Checks if there are any mojibakes inside the line
        # You must mojibake before removing control chars! Some control chars
        # are part of a valid mojibake.
        if config["mojibake"]:
            status, line_decoded = clean_mojibake(line_decoded)
            add_to_log(f"Clean_mojibake; found a mojibake; {line_decoded}{linesep}", status)

        # Delete leading and trailing newline characters
        if config["newline"]:
            status, line_decoded = clean_newline(line_decoded)
            add_to_log(f"Clean_newline; deleted newline characters; {line_decoded!r}{linesep}", status)

        # Checks if there are any control chars inside line
        if config["check_controlchar"]:
            status, cc = check_controlchar(line_decoded)
            add_to_log(
                f"Check_controlchar; found controlchar {cc!r}; {line_decoded!r}{linesep}", status, require_debug=False
            )

            if status:
                continue

        # Check if there are named html chars in the line
        if config["html_named"]:
            status, line_decoded = clean_html_named(line_decoded)

            add_to_log(f"Clean_html_named; found named html character; {line_decoded}{linesep}", status)

        # Delete leading and trailing character sequences representing a newline
        if config["trim"]:
            status, line_decoded = clean_trim(line_decoded)

            add_to_log(f"Clean_trim; found trim sequence; {line_decoded!r}{linesep}", status)

        # Should we do the cut?
        if config["cut"]:
            status, line_decoded = clean_cut(line_decoded, config["delimiter"], config["cut_fields"])

            add_to_log(f"Clean_cut; field cutted; {line_decoded}{linesep}", status)

        # Replace umlauts
        if config["umlaut"]:
            status, line_decoded = clean_add_umlaut(line_decoded)

            add_to_log(f"Clean_umlaut; umlaut replaced; {line_decoded}{linesep}", status)

        # Replace non-ascii
        if config["non_ascii"]:
            status, line_decoded = clean_non_ascii(line_decoded)

            add_to_log(f"Clean_non_ascii; non-ascii replaced; {line_decoded}{linesep}", status)

        # Replace all letters with lowercase
        if config["lowercase"]:
            status, line_decoded = clean_lowercase(line_decoded)

            add_to_log(f"Clean_lowercase; all capitals replaced; {line_decoded}{linesep}", status, require_verbose=True)

        # Replace first letter of a word to a uppercase letter
        if config["title_case"]:
            status, line_decoded = clean_title_case(line_decoded)

            add_to_log(f"Clean_title_case; first letter of a word to uppercase; {line_decoded}{linesep}", status)

        # Should we remove emails?
        if config["remove_email"]:
            status, line_decoded = remove_email(line_decoded)

            add_to_log(f"Remove_email; email found; {line_decoded}{linesep}", status)

        if config["googlengram"]:
            status, line_decoded = clean_googlengram(line_decoded)

            add_to_log(f"Clean_googlengram; removed speechtags; {line_decoded}{linesep}", status)

        if config["check_case"]:
            status, c = check_case(line_decoded)

            failed = not status

            add_to_log(f"Check_case; dropped line because of {c}; {line_decoded}{linesep}", failed)

            if failed:
                continue

        if config["check_length"]:
            if not check_length(line_decoded, config["check_min_length"], config["check_max_length"]):
                add_to_log(
                    f"Check_length; dropped line because of failed length check; {line_decoded}{linesep}",
                    require_debug=False,
                )
                continue

        if config["check_email"]:
            if not check_email(line_decoded):
                add_to_log(
                    f"Check_email; dropped line because found email; {line_decoded}{linesep}", require_debug=False
                )
                continue

        if config["check_hash"]:
            if not check_hash(line_decoded):
                add_to_log(
                    f"Check_hash; dropped line because found a hash; {line_decoded}{linesep}", require_debug=False
                )
                continue

        if config["check_mac_address"]:
            if not check_mac_address(line_decoded):
                add_to_log(
                    f"Check_mac_address; dropped line because found a MAC address; {line_decoded}{linesep}",
                    require_debug=False,
                )
                continue

        if config["check_non_ascii"]:
            if not check_non_ascii(line_decoded):
                add_to_log(
                    f"Check_non_ascii; dropped line because non ascii char found; {line_decoded}{linesep}",
                    require_debug=False,
                )
                continue

        if config["check_replacement_character"]:
            if check_character(line_decoded, "�"):
                add_to_log(
                    f"Check_replacement_character; dropped line because '�' found; {line_decoded}{linesep}",
                    require_debug=False,
                )
                continue

        if config["check_regex"]:
            if not check_regex(line_decoded, config["check_regex"]):
                add_to_log(
                    f"Check_regex; dropped line because does not match regex; {line_decoded}{linesep}",
                    require_debug=False,
                )
                continue

        min_digits = config["check_min_digits"]
        max_digits = config["check_max_digits"]

        if min_digits > 0:
            if not contains_at_least(line_decoded, min_digits, str.isdigit):
                add_to_log(
                    f"Check_min_digits; dropped line because contains less than {min_digits} digits;"
                    f" {line_decoded}{linesep}",
                    require_debug=False,
                )
                continue

        if max_digits != float("inf"):
            if not contains_at_most(line_decoded, max_digits, str.isdigit):
                add_to_log(
                    f"Check_max_digits; dropped line because contains more than {max_digits} digits;"
                    f" {line_decoded}{linesep}",
                    require_debug=False,
                )
                continue

        min_uppercase = config["check_min_uppercase"]
        max_uppercase = config["check_max_uppercase"]

        if min_uppercase > 0:
            if not contains_at_least(line_decoded, min_uppercase, str.isupper):
                add_to_log(
                    f"Check_min_uppercase; dropped line because contains less than {min_uppercase} uppercase"
                    f" characters; {line_decoded}{linesep}",
                    require_debug=False,
                )
                continue

        if max_uppercase != float("inf"):
            if not contains_at_most(line_decoded, max_uppercase, str.isupper):
                add_to_log(
                    f"Check_max_uppercase; dropped line because contains more than {max_uppercase} uppercase"
                    f" characters; {line_decoded}{linesep}",
                    require_debug=False,
                )
                continue

        min_specials = config["check_min_specials"]
        max_specials = config["check_max_specials"]

        if min_specials:
            if not contains_at_least(
                line_decoded, min_specials, lambda char: not char.isalnum() and not char.isspace()
            ):
                add_to_log(
                    f"Check_min_specials; dropped line because contains less than {min_specials} special characters;"
                    f" {line_decoded}{linesep}",
                    require_debug=False,
                )
                continue

        if max_specials != float("inf"):
            if not contains_at_most(line_decoded, max_specials, lambda char: not char.isalnum() and not char.isspace()):
                add_to_log(
                    f"Check_max_specials; dropped line because contains more than {max_specials} special characters;"
                    f" {line_decoded}{linesep}",
                    require_debug=False,
                )
                continue

        if config["check_starting_with"]:
            to_check = config["check_starting_with"]
            if check_starting_with(line_decoded, to_check):
                add_to_log(
                    f"Check_starting_with; dropped line because {to_check} found; {line_decoded}{linesep}",
                    require_debug=False,
                )
                continue

        if config["check_uuid"]:
            if not check_uuid(line_decoded):
                add_to_log(
                    f"Check_uuid; dropped line because found a uuid; {line_decoded}{linesep}", require_debug=False
                )
                continue

        if config["check_ending_with"]:
            to_check = config["check_ending_with"]
            if check_ending_with(line_decoded, to_check):
                add_to_log(
                    f"Check_ending_with; dropped line because {to_check} found; {line_decoded}{linesep}",
                    require_debug=False,
                )
                continue

        if config["check_contains"]:
            to_check = config["check_contains"]
            if check_contains(line_decoded, to_check):
                add_to_log(
                    f"Check-contains; dropped line because {to_check} found; {line_decoded}{linesep}",
                    require_debug=False,
                )
                continue

        if config["check_empty_line"]:
            if check_empty_line(line_decoded):
                add_to_log(
                    "Check_empty_line; dropped line because is empty or only contains whitespace;"
                    f" {line_decoded}{linesep}",
                    require_debug=False,
                )
                continue

        if config["remove_punctuation"]:
            status, line_decoded = remove_punctuation(line_decoded, config["punctuation"])
            add_to_log(f"Remove_punctuation; stripped punctuation; {line_decoded}{linesep}", status)

        if config["remove_strip_punctuation"]:
            status, line_decoded = remove_strip_punctuation(line_decoded, config["punctuation"])
            add_to_log(f"Remove_strip_punctuation; stripped punctuation; {line_decoded}{linesep}", status)

        # Some clean modules will modify the end result, those modification will be added here.
        # They will be added to the running thread, this might cause one thread to have more work
        # then others.
        if config["add_split"]:
            modified_lines = add_split(line_decoded)

            for modified_line in modified_lines:
                add_to_lines(modified_line)
                add_to_log(f"Add_split; new line because of split; {modified_line}{linesep}")

        if config["add_lower"]:
            modified_line = add_lower(line_decoded)
            add_to_lines(modified_line)
            add_to_log(f"Add_lower; new line; {modified_line}{linesep}", modified_line is not None)

        if config["add_first_upper"]:
            modified_line = add_first_upper(line_decoded)
            add_to_lines(modified_line)
            add_to_log(f"Add_first_upper; new line; {modified_line}{linesep}", modified_line is not None)

        if config["add_title_case"]:
            modified_line = add_title_case(line_decoded)
            add_to_lines(modified_line)
            add_to_log(f"Add_title_case; new line; {modified_line}{linesep}", modified_line is not None)

        if config["add_latin_ligatures"]:
            modified_line = add_latin_ligatures(line_decoded)
            add_to_lines(modified_line)
            add_to_log(f"Add_latin_ligatures; new line; {modified_line}{linesep}", modified_line is not None)

        if config["add_umlaut"]:
            status, modified_line = clean_add_umlaut(line_decoded)
            add_to_lines(modified_line, status)
            add_to_log(f"Add_umlaut; new line; {modified_line}{linesep}", status)

        if config["add_without_punctuation"]:
            modified_line = add_without_punctuation(line_decoded, config["punctuation"])
            add_to_lines(modified_line)
            add_to_log(f"Add_without_punctuation; new line; {modified_line}{linesep}", modified_line is not None)

        add_to_log(f"----END LINE---- {line_decoded}{linesep}")

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

        chunk = []
        current_size = 0

        while True:
            # Use select to wait for data up to 'timeout' seconds.
            r, _, _ = select.select([filename], [], [], 5)
            if r:
                # Read one line at a time
                line = filename.readline()
                if not line:
                    # EOF reached; yield what we have and break.
                    if chunk:
                        yield chunk
                    break

                # Append the line to the current chunk.
                chunk.append(line.rstrip(b"\n"))
                current_size += len(line)

                # If we've reached the desired size, yield the chunk and reset.
                if current_size >= size:
                    yield chunk
                    chunk = []
                    current_size = 0
            else:
                # No data available within the timeout period.
                if chunk:
                    yield chunk
                break


# Quick to default logging to stderr instead
def stderr_print(config: Config, *args, **kwargs):
    """Print to stderr"""
    if config["verbose"] is True:
        kwargs.setdefault("file", sys.stderr)
        print(*args, **kwargs)


def parse_arguments():
    """Parse the arguments"""
    parser = argparse.ArgumentParser(description="Demeuk - a simple tool to clean up corpora")
    parser.add_argument("-i", "--input-file", help="Specify the input file to be cleaned, or provide a glob pattern.")
    parser.add_argument("-o", "--output-file", help="Specify the output file to write the cleaned data to.")
    parser.add_argument("-l", "--log", help="Specify the log file to write the log data to.")
    parser.add_argument("-j", "--threads", help="Specify the number of threads to use.", default="all")
    parser.add_argument("--input-encodings", help="Specify the input encodings to use.", default=["utf-8"], nargs="+")
    parser.add_argument("--output-encoding", help="Specify the output encoding to use.", default="utf-8")
    parser.add_argument("-v", "--verbose", help="Enable verbose output.", action="store_true")
    parser.add_argument("--debug", help="Enable debug output.", action="store_true")
    parser.add_argument("--progress", help="Enable progress output.", action="store_true")
    parser.add_argument("-n", "--limit", help="Limit the number of lines per thread", default=False)
    parser.add_argument("-s", "--skip", help="Skip the first n lines", default=0, type=int)
    parser.add_argument("--punctuation", help="Specify the punctuation to remove", default=string_punctuation + " ")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("-c", "--cut", help="Cut the line based on the delimiter", action="store_true")
    parser.add_argument("--cut-before", help="Cut the line before the delimiter", action="store_true")
    parser.add_argument("-f", "--cut-fields", help="Specify the fields to cut", default="2-")
    parser.add_argument("-d", "--delimiter", help="Specify the delimiter to use", default=[":"], nargs="+")
    parser.add_argument("--check-min-length", help="Check the minimum length of the line", default=0, type=int)
    parser.add_argument("--check-max-length", help="Check the maximum length of the line", default=0, type=int)
    parser.add_argument("--check-case", help="Check if the line is all uppercase", action="store_true")
    parser.add_argument(
        "--check-controlchar", help="Check if the line contains control characters", action="store_true"
    )
    parser.add_argument("--check-email", help="Check if the line contains an email address", action="store_true")
    parser.add_argument("--check-hash", help="Check if the line contains a hash", action="store_true")
    parser.add_argument("--check-mac-address", help="Check if the line contains a MAC address", action="store_true")
    parser.add_argument(
        "--check-non-ascii", help="Check if the line contains non-ascii characters", action="store_true"
    )
    parser.add_argument("--check-uuid", help="Check if the line contains a UUID", action="store_true")
    parser.add_argument(
        "--check-replacement-character", help="Check if the line contains a replacement character", action="store_true"
    )
    parser.add_argument("--check-starting-with", help="Check if the line starts with a specific character", nargs="+")
    parser.add_argument("--check-ending-with", help="Check if the line ends with a specific character", nargs="+")
    parser.add_argument("--check-contains", help="Check if the line contains a specific character", nargs="+")
    parser.add_argument("--check-empty-line", help="Check if the line is empty", action="store_true")
    parser.add_argument("--check-regex", help="Check if the line matches a specific regex", nargs="+")
    parser.add_argument("--check-min-digits", help="Check if the line contains at least n digits", default=0, type=int)
    parser.add_argument(
        "--check-max-digits", help="Check if the line contains at most n digits", default=float("inf"), type=float
    )
    parser.add_argument(
        "--check-min-uppercase", help="Check if the line contains at least n uppercase characters", default=0, type=int
    )
    parser.add_argument(
        "--check-max-uppercase",
        help="Check if the line contains at most n uppercase characters",
        default=float("inf"),
        type=float,
    )
    parser.add_argument(
        "--check-min-specials", help="Check if the line contains at least n special characters", default=0, type=int
    )
    parser.add_argument(
        "--check-max-specials",
        help="Check if the line contains at most n special characters",
        default=float("inf"),
        type=float,
    )
    parser.add_argument("--hex", help="Decode hex strings", action="store_true")
    parser.add_argument("--html", help="Decode html entities", action="store_true")
    parser.add_argument("--html-named", help="Decode named html entities", action="store_true")
    parser.add_argument("--lowercase", help="Convert all characters to lowercase", action="store_true")
    parser.add_argument("--title-case", help="Convert the first letter of each word to uppercase", action="store_true")
    parser.add_argument("--umlaut", help="Replace umlauts", action="store_true")
    parser.add_argument("--mojibake", help="Decode mojibake", action="store_true")
    parser.add_argument("--decode", help="Try to decode the line", action="store_true")
    parser.add_argument("--tab", help="Replace tab characters with ':' greedy", action="store_true")
    parser.add_argument("--newline", help="Remove leading and trailing newline characters", action="store_true")
    parser.add_argument("--non-ascii", help="Replace non-ascii characters", action="store_true")
    parser.add_argument("--trim", help="Remove leading and trailing whitespace", action="store_true")
    parser.add_argument("--add-lower", help="Add a line with all characters in lowercase", action="store_true")
    parser.add_argument(
        "--add-first-upper", help="Add a line with the first character in uppercase", action="store_true"
    )
    parser.add_argument(
        "--add-title-case", help="Add a line with the first letter of each word in uppercase", action="store_true"
    )
    parser.add_argument("--add-latin-ligatures", help="Add a line with latin ligatures", action="store_true")
    parser.add_argument("--add-split", help="Add a line with split words", action="store_true")
    parser.add_argument("--add-umlaut", help="Add a line with umlauts", action="store_true")
    parser.add_argument("--add-without-punctuation", help="Add a line without punctuation", action="store_true")
    parser.add_argument("--remove-strip-punctuation", help="Remove punctuation", action="store_true")
    parser.add_argument("--remove-punctuation", help="Remove punctuation", action="store_true")
    parser.add_argument("--remove-email", help="Remove email addresses", action="store_true")
    parser.add_argument("-g", "--googlengram", help="Remove speech tags", action="store_true")
    parser.add_argument("--leak", help="Leak the first line of the file", action="store_true")
    parser.add_argument("--leak-full", help="recommended when working with leaks", action="store_true")

    args = parser.parse_args()

    threads = args.threads

    if threads == "all":
        threads = cpu_count()
    else:
        threads = int(threads)

    if args.cut_fields == "2-" and args.cut_before:
        args.cut_fields = "-1"

    delimiters: list[str] = []
    for delimiter in args.delimiter:
        if " " in delimiter:
            delimiters.extend(delimiter.split(" "))
        else:
            delimiters.append(delimiter)

    config: Config = {
        "input_file": args.input_file,
        "output_file": args.output_file,
        "log": args.log,
        "threads": threads,
        "input_encoding": args.input_encodings,
        "output_encoding": args.output_encoding,
        "verbose": args.verbose,
        "debug": args.debug,
        "progress": args.progress,
        "limit": int(args.limit) if args.limit else False,
        "skip": args.skip,
        "punctuation": args.punctuation,
        "cut": args.cut,
        "cut_before": args.cut_before,
        "cut_fields": args.cut_fields,
        "delimiter": delimiters,
        "check_min_length": args.check_min_length,
        "check_max_length": args.check_max_length,
        "check_length": args.check_min_length or args.check_max_length,
        "check_case": args.check_case,
        "check_controlchar": args.check_controlchar,
        "check_email": args.check_email,
        "check_hash": args.check_hash,
        "check_mac_address": args.check_mac_address,
        "check_non_ascii": args.check_non_ascii,
        "check_uuid": args.check_uuid,
        "check_replacement_character": args.check_replacement_character,
        "check_starting_with": args.check_starting_with,
        "check_ending_with": args.check_ending_with,
        "check_contains": args.check_contains,
        "check_empty_line": args.check_empty_line,
        "check_regex": args.check_regex,
        "check_min_digits": args.check_min_digits,
        "check_max_digits": args.check_max_digits,
        "check_min_uppercase": args.check_min_uppercase,
        "check_max_uppercase": args.check_max_uppercase,
        "check_min_specials": args.check_min_specials,
        "check_max_specials": args.check_max_specials,
        "hex": args.hex,
        "html": args.html,
        "html_named": args.html_named,
        "lowercase": args.lowercase,
        "title_case": args.title_case,
        "umlaut": args.umlaut,
        "mojibake": args.mojibake,
        "decode": args.decode,
        "tab": args.tab,
        "newline": args.newline,
        "non_ascii": args.non_ascii,
        "trim": args.trim,
        "add_lower": args.add_lower,
        "add_first_upper": args.add_first_upper,
        "add_title_case": args.add_title_case,
        "add_latin_ligatures": args.add_latin_ligatures,
        "add_split": args.add_split,
        "add_umlaut": args.add_umlaut,
        "add_without_punctuation": args.add_without_punctuation,
        "remove_strip_punctuation": args.remove_strip_punctuation,
        "remove_punctuation": args.remove_punctuation,
        "remove_email": args.remove_email,
        "googlengram": args.googlengram,
        "leak": args.leak,
        "leak_full": args.leak_full,
    }

    if config["googlengram"]:
        config["cut"] = False
        config["remove_email"] = False
        config["decode"] = True
        config["mojibake"] = False
        config["check_controlchar"] = False
        config["tab"] = False

    if config["leak"]:
        config["mojibake"] = True
        config["decode"] = True
        config["newline"] = True
        config["check_controlchar"] = True

    if config["leak_full"]:
        config["leak"] = True
        config["mojibake"] = True
        config["decode"] = True
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

    if not config["input_file"]:
        config["verbose"] = False
        config["debug"] = False

    return config


def main():  # pylint: disable=R0912:too-many-branches
    """Main function"""
    config = parse_arguments()

    if config["progress"]:
        if config["verbose"] or config["debug"]:
            stderr_print(config, "Progress can not be used with verbose or debug")
            sys.exit(2)

    input_files_data: list[InputFileData] = []
    if config["input_file"]:
        stderr_print(config, f"Main: input found in {config['input_file']}")
        input_files = tqdm(
            glob(config["input_file"], recursive=True),
            desc="Files processed",
            mininterval=0.1,
            unit=" files",
            disable=not config["progress"],
            position=0,
        )

        if not access(os.path.dirname(config["input_file"]), R_OK):
            stderr_print(config, f"Cannot read input file from {config['input_file']}")
            sys.exit(1)

        for input_file in input_files:
            if not access(input_file, R_OK):
                stderr_print(config, f"Cannot read input file from {input_file}")
                sys.exit(1)

            chunk_estimation = int(ceil(path.getsize(input_file) / CHUNK_SIZE))

            input_files_data.append({"file": input_file, "chunk_estimation": chunk_estimation})
    else:
        stderr_print(config, "Main: no input file found using stdin")
        # Instead of reading all data from stdin, we pass sys.stdin.buffer directly
        # and leave chunk_estimation as None because we cannot determine its length ahead of time.
        input_files_data.append({"file": sys.stdin.buffer, "chunk_estimation": None})

    if config["output_file"] and not access(path.dirname(config["output_file"]), W_OK):
        stderr_print(config, f"Cannot write output file to {config['output_file']}")
        sys.exit(1)

    if config["log"] and not (access(config["log"], F_OK) or access(path.dirname(config["log"]), W_OK)):
        stderr_print(config, f"Cannot write log file to {config['log']}")
        sys.exit(1)

    #  Main worker
    stderr_print(config, f"Main: running demeuk - {VERSION}")
    stderr_print(config, f"Main: Using {config['threads']} core(s) of total available cores: {cpu_count()}")
    stderr_print(config, f"Main: start chunking file {config['input_file'] or 'stdin'}")

    if config["output_file"]:
        stderr_print(config, f"Main: output found in {config['output_file']}")
        output_file = open(config["output_file"], "w", encoding=config["output_encoding"])
    else:
        output_file = sys.stdout

    if config["log"]:
        stderr_print(config, f"Main: logs found in {config['log']}")
        log_file = open(config["log"], "a", encoding="utf-8")
    else:
        log_file = sys.stderr

    stderr_print(config, "Main: processing started.")

    def write_results(results: list[str]):
        output_file.writelines(results)
        output_file.flush()

    def write_log(log: list[str] | str):
        if config["debug"] or config["verbose"] or config["log"]:
            log_file.writelines(log)
            log_file.flush()

    def write_results_and_log(async_result: dict[str, list[str]]):
        write_results(async_result["results"])
        write_log(async_result["log"])

    write_log(f"Running demeuk - {VERSION}{linesep}")

    with Manager() as manager:
        task_queue = manager.Queue(config["threads"])
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
                    result = clean_up(config, chunk)
                    write_results_and_log(result)
                finally:
                    task_queue.task_done()

        for _ in range(config["threads"]):
            process = Process(target=worker)
            process.start()
            processes.append(process)

        for input_file_data in input_files_data:
            for chunk in tqdm(
                chunkify(input_file_data["file"], config, CHUNK_SIZE),
                mininterval=1,
                unit=" chunks",
                disable=not config["progress"],
                total=input_file_data["chunk_estimation"],
                position=1,
            ):
                if not chunk:
                    continue

                task_queue.put(chunk)

        stderr_print(config, "Main: done submitting all jobs, waiting for threads to finish")

        for _ in processes:
            task_queue.put(None)

        for process in processes:
            process.join()

        stderr_print(config, "Main: all done")

    if output_file is not sys.stdout:
        output_file.close()

    if log_file is not sys.stderr:
        log_file.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("ERROR: Process terminated by user! (CTRL+C)")
        sys.exit(3)
