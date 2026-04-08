from unicodedata import category
from re import search

from modules.regexes import *

def check_regex(line, regexes):
    """Checks if a line matches a comma-separated list of regexes

    Params:
        line (unicode)
        regexes (str)

    Returns:
        true if all regexes match
        false if line does not match regex
    """
    regexes = regexes.split(',')
    for regex in regexes:
        if search(regex, line):
            continue
        else:
            return False
    return True


def contains_at_least(line, bound, char_property):
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


def check_min_digits(line, n):
    return contains_at_least(line, n, str.isdigit)


def check_min_uppercase(line, n):
    return contains_at_least(line, n, str.isupper)


def check_min_specials(line, n):
    return contains_at_least(line, n, lambda c: not c.isalnum() and not c.isspace())


def contains_at_most(line, bound, char_property):
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


def check_max_digits(line, n):
    return contains_at_most(line, n, str.isdigit)


def check_max_uppercase(line, n):
    return contains_at_most(line, n, str.isupper)


def check_max_specials(line, n):
    return contains_at_most(line, n, lambda c: not c.isalnum() and not c.isspace())

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


def check_min_length(line, n):
    return check_length(line, min=n)


def check_max_length(line, n):
    return check_length(line, max=n)


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



def check_replacement_character(line):
    return check_character(line, '�')

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


def check_contains(line, strings):
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
