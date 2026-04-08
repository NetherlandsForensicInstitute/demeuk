from unicodedata import category
from ftfy.chardata import HTML_ENTITY_RE, HTML_ENTITIES
from re import compile as re_compile
from re import search
from re import sub

from modules.regexes import *



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


def clean_transliterate(line, language):
    """Transliterate a string

    Params:
        line (Unicode)
        language (str)

    Returns:
        line (Unicode)
    """
    cleaned_line = translit(line, language, reversed=True)
    if line != cleaned_line:
        return True, cleaned_line
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
