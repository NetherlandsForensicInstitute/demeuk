### - Modify module -
# Modify modules modify a line
# Module signature is the same as that of a remove module
from binascii import unhexlify
from html import unescape
from unicodedata import category

from chardet import detect
from ftfy.fixes import fix_encoding
from ftfy.chardata import HTML_ENTITY_RE, HTML_ENTITIES

from transliterate import translit
from unidecode import unidecode

from modules.add import clean_add_umlaut
from modules.regexes import *

# TODO
# This should become a member of an instantiated Module later.
# For now we need a way to "configure" a module
# Want to do it only once, not every loop.
# So for now use a global variable.
modify_store_input_encoding = ['UTF-8']

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
        return True, return_line, f'Clean_html_named; found named html character'
    else:
        return False, line, None

global_store_delims = [':']
global_store_cut_fields = '2-'

def set_delim(delim):
    global global_store_delims
    global_store_delims = delim


def set_cut_fields(cut_fields):
    global global_store_cut_fields
    global_store_cut_fields = cut_fields

def clean_cut(line):
    """Finds the first delimiter and returns the remaining string either after
    or before the delimiter.

    Params:
        line (unicode)
        delimiters list(unicode)
        fields (unicode)

    Returns:
        line (unicode)
    """
    for delimiter in global_store_delims:
        if delimiter in line:
            if '-' in global_store_cut_fields:
                start = global_store_cut_fields.split('-')[0]
                stop = global_store_cut_fields.split('-')[1]
                if start == '':
                    start = 1
                if stop == '':
                    stop = len(line)
                fields = slice(int(start) - 1, int(stop))
            else:
                fields = slice(int(global_store_cut_fields) - 1, int(global_store_cut_fields))
            return True, delimiter.join(line.split(delimiter)[fields]), f'Clean_cut; field cutted'
    else:
        return False, line, None


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
        return True, cleaned_line, f'Clean_transliterate; transliterated';
    else:
        return False, line, None


def clean_non_ascii(line):
    """Replace non ascii chars with there ascii representation.

    Params:
        line (Unicode)

    Returns:
        line (Unicode)
    """
    cleaned_line = unidecode(line)
    if line != cleaned_line:
        return True, cleaned_line, f'Clean_non_ascii; non-ascii replaced'
    else:
        return False, line, None


def clean_lowercase(line):
    """Replace all capitals to lowercase

        Params:
            line (Unicode)

        Returns:
            line (Unicode)

        """
    cleaned_line = line.lower()
    if line != cleaned_line:
        return True, cleaned_line, f'Clean_lowercase; all capitals replaced'
    else:
        return False, line, None


def clean_title_case(line):
    """Replace words to title word (uppercasing first letter)

    Params:
        line (Unicode)

    Returns:
        line (Unicode)

    """
    cleaned_line = line.title()
    if line != cleaned_line:
        # Verbose message was a typo in original
        return True, cleaned_line, f'Clean_title_case; lowercase characters replaced'
    else:
        return False, line, None


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
        return True, cleaned_line, f'Clean_trim; found trim sequence'
    else:
        return False, line, None


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
        return True, return_line, f'Clean_newline; deleted newline characters'
    else:
        return False, line, None


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
        return True, return_line, f'Clean_mojibake; found a mojibake'
    else:
        return False, line, None


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


def set_input_encoding(input_encoding):
    global modify_store_input_encoding
    modify_store_input_encoding = input_encoding.split(',')


def clean_encode(line):
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
    line = line.encode() # TODO What do we do here? strings are already decoded.
    line_decoded = line # If nothing works.
    for encoding in modify_store_input_encoding:
        line = try_encoding(line, encoding)
        if line is not False:
            break
    # All other methods failed, lets run the detect library on the line and try to guess the encoding.
    if line is False:
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

def clean_umlaut(line):
    status, result = clean_add_umlaut(line)
    if status:
        return True, result, f'Clean_umlaut; umlaut replaced'
    else:
        return False, result, None