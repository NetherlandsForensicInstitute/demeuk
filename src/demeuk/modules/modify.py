# - Modify module -
# Modify modules modify a line
# Module signature is the same as that of a remove module
from binascii import unhexlify
from html import unescape
from re import sub
from unicodedata import category

from chardet import detect
from ftfy import fix_encoding
from ftfy.chardata import HTML_ENTITIES, HTML_ENTITY_RE
from transliterate import translit
from unidecode import unidecode

from .base import *
from ..regexes import HEX_REGEX, TRIM_BLOCKS
from .add import clean_add_umlaut

class ModifyModule(Module):

    @staticmethod
    def get_parser_group():
        return 'modify'

    @staticmethod
    def get_pipeline_position():
        return PipelinePosition.AFTER_ENCODE

    def handle(self, result):
        return Actions(
            update=result.update,
            debug_str=result.msg,
        )

    def get_result(self, line, cleaned_line):
        if line != cleaned_line:
            return Result(status=True, msg=self.debug_str, update=cleaned_line)
        return Result(status=False, msg=None)

class CleanTrimModifyModule(ModifyModule):
    TRIM_BLOCKS = ('\\\\n', '\\\\r', '\\n', '\\r', '<br>', '<br />')

    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='trim',
            help_str="Remove whitespace from beginning and end of line. Whitespace detected is '\\\\n', '\\\\r', '\\n', '\\r', '<br>' and '<br />'."
        )

    @property
    def debug_str(self):
        return 'Clean Trim; found trim sequence'

    def run(self, line):
        cleaned_line = line
        # Ensure removal of duplicated blocks
        while True:
            has_match = False
            for x in self.TRIM_BLOCKS:
                if cleaned_line.startswith(x):
                    cleaned_line = cleaned_line[len(x):]
                    has_match = True

                if cleaned_line.endswith(x):
                    cleaned_line = cleaned_line[:-len(x)]
                    has_match = True

            if not has_match:
                break

        return self.get_result(line, cleaned_line)


# TODO add argparse thing where option can only take certain arguments
class TransliterateModifyModule(ModifyModule, ParamModule):
    @staticmethod
    def get_help_info():
        return HelpInfoParam(
            option='transliterate',
            help_str="Transliterate a string, for example 'ipsum' becomes 'իպսում'. The following languages are supported: ka, sr, l1, ru, mn, uk, mk, el, hy and bg.",
            metavar='<language>',
            param_type=str)

    @property
    def debug_str(self):
        return 'Clean transliterate; transliterated'

    def run(self, line):
        # TODO ipsum is not transliterated to ... because it is reversed. Other way around?
        cleaned_line = translit(line, self._param, reversed=True)

        return self.get_result(line, cleaned_line)




class HexModule(Module):

    HEX_REGEX = re_compile(r'^\$(?:HEX|hex)\[((?:[0-9a-fA-F]{2})+)\]$')


    @staticmethod
    def get_help_info() -> HelpInfo | HelpInfoParam:
        return HelpInfo(
            option='hex',
            help_str='Replace lines like: $HEX[41424344] with ABCD.'
        )

    @property
    def debug_str(self) -> str:
        return 'Clean hex; replaced $HEX[], added to queue and quitting'

    def run(self, line):
        match = self.HEX_REGEX.search(line)
        if match:
            return Result(status=True, msg=self.debug_str, add=unhexlify(match.group(1)))
        return Result(status=False, msg=None)

    def handle(self, result):
        return Actions(
            add=[result.add], # expects a list.
            debug_str=result.msg,
            stop=True,
            do_not_re_encode=True)

    @staticmethod
    def get_pipeline_position():
        return PipelinePosition.AFTER_ENCODE

    @staticmethod
    def get_parser_group():
        return 'modify'

class TabModule(ModifyModule):
    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='tab',
            help_str="Enables replacing tab char with ':', sometimes leaks contain both ':' and '\\t'."
        )

    # This module runs on bytes
    @staticmethod
    def get_pipeline_position():
        return PipelinePosition.BEFORE_ENCODE

    @property
    def debug_str(self) -> str:
        return 'Clean_tab; replaced tab characters'

    def run(self, line):
        if b'\x09' in line:
            line = sub(b'\x09+', b'\x3a', line)
            return Result(status=True, msg=self.debug_str, update=line)
        return Result(status=False, msg=None)
# Note on global variables:
# This should become a member of an instantiated Module later.
# For now we need a way to "configure" a module
# Want to do it only once, not every loop.
# So for now use a global variable.
global_store_input_encoding = ['UTF-8']


def set_input_encoding(input_encoding):
    global global_store_input_encoding
    global_store_input_encoding = input_encoding.split(',')


def get_input_encoding():
    return global_store_input_encoding


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

        # If html.unescape only decoded part of the string, that's not what we want. The semicolon should be consumed.
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
        return True, unhexlify(match.group(1)), 'Clean_hex; replaced $HEX[], added to queue and quitting'
    else:
        return False, line, None


def clean_html(line):
    """Detects html encode chars and decodes them

    Params:
        line (Unicode)

    Returns:
        line (Unicode)
    """
    return_line = HTML_ENTITY_RE.sub(_unescape_fixup, line)
    if return_line != line:
        return True, return_line, 'Clean_html; replaced html, added to queue and quitting'
    else:
        return False, line, None


def clean_html_named(line):
    """Detects named html encode chars and decodes them

    Params:
        line (Unicode)

    Returns:
        line (Unicode)
    """
    return_line = HTML_ENTITY_RE.sub(_unescape_fixup_named, line)
    if return_line != line:
        return True, return_line, 'Clean_html_named; found named html character'
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
        return True, cleaned_line, 'Clean_transliterate; transliterated'
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
        return True, cleaned_line, 'Clean_non_ascii; non-ascii replaced'
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
        return True, cleaned_line, 'Clean_lowercase; all capitals replaced'
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
        return True, cleaned_line, 'Clean_title_case; lowercase characters replaced'
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

        if not has_match:
            break

    if line != cleaned_line:
        return True, cleaned_line, 'Clean_trim; found trim sequence'
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
        return True, line, 'Clean_tab; replaced tab characters'
    else:
        return False, line, None


def clean_newline(line):
    """Delete newline characters at start and end of line

    Params:
        line (Unicode)

    Returns:
        line (Unicode)
    """
    return_line = line.strip('\r\n')
    if return_line != line:
        return True, return_line, 'Clean_newline; deleted newline characters'
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
        return True, return_line, 'Clean_mojibake; found a mojibake'
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
        # Some encodings will decode almost any line, let's check if we have invalid chars.
        # If we have invalid chars (except for tab-like chars) we will fail
        for c in line_decoded:
            if category(c) in ['Cc', 'Cf', 'Cn', 'Co', 'Cs']:
                if c == '\t' or c == '\f':
                    continue
                else:
                    return False
        return line_decoded
    except UnicodeDecodeError:
        return False


def clean_encode(line):
    """Detects and tries encoding

    Params:
        line (bytes)

    Returns:
        Decoded UTF-8 string
    """
    # Try either a user set of encodings or the default encoding set.
    # When using multiple encoding is it better to have multibyte encodings before
    # single-byte encodings. Also it is better to not include iso encoding by default.
    # https://en.wikipedia.org/wiki/Character_encoding#Common_character_encodings
    # Input_encoding is by default [utf8]
    for encoding in get_input_encoding():
        line_decoded = try_encoding(line, encoding)
        if line_decoded is not False:
            break
    # All other methods failed, lets run the detect library on the line and try to guess the encoding.
    if line_decoded is False:
        encode = detect(line)
        if encode.get('encoding'):
            try:
                line_decoded = line.decode(encode['encoding'])
                return True, line_decoded
            except (UnicodeDecodeError, LookupError) as e:  # noqa F841
                return False, encode['encoding']
        else:
            return False, 'Unknown'
    # If we managed to get here, return decode line
    return True, line_decoded


def clean_umlaut(line):
    status, result = clean_add_umlaut(line)
    if status:
        return True, result, 'Clean_umlaut; umlaut replaced'
    else:
        return False, result, None
