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

from ..base import *
from ..add.add import clean_add_umlaut

class ModifyModule(Module):

    @staticmethod
    def get_pipeline_position():
        return PipelinePosition.AFTER_ENCODE

    def handle(self, result):
        return Actions(
            update=result.update,
            debug_str=result.msg,
        )

    @property
    def debug_str(self):
        return 'modified line'

    def get_result(self, line, cleaned_line):
        if line != cleaned_line:
            return Result(status=True, msg=self.debug_str, update=cleaned_line)
        return Result(status=False, msg=None)

class TrimModule(ModifyModule):
    TRIM_BLOCKS = ('\\\\n', '\\\\r', '\\n', '\\r', '<br>', '<br />')

    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='trim',
            help_str="Remove whitespace from beginning and end of line. Whitespace detected is '\\\\n', '\\\\r', '\\n', '\\r', '<br>' and '<br />'."
        )

    @property
    def debug_str(self):
        return 'Modify:\tTrim:\t\tfound trim sequence'

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
class TransliterateModule(ModifyModule, ParamModule):
    @staticmethod
    def get_help_info():
        return HelpInfoParam(
            option='transliterate',
            help_str="Transliterate a string, for example 'ipsum' becomes 'իպսում'. The following languages are supported: ka, sr, l1, ru, mn, uk, mk, el, hy and bg.",
            metavar='<language>',
            param_type=str)

    @property
    def debug_str(self):
        return 'Clean:\tTransliterate:\ttransliterated'

    def run(self, line):
        # TODO ipsum is not transliterated to ... because it is reversed. Other way around?
        cleaned_line = translit(line, self._param, reversed=True)

        return self.get_result(line, cleaned_line)





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
        return 'Clean:\tTab\t\treplaced tab characters'

    def run(self, line):
        if b'\x09' in line:
            line = sub(b'\x09+', b'\x3a', line)
            return Result(status=True, msg=self.debug_str, update=line)
        return Result(status=False, msg=None)

class MojibakeModule(ModifyModule):
    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='mojibake',
            help_str='Fixes mojibakes, which means lines like SmˆrgÂs will be fixed to Smörgås.')

    @property
    def debug_str(self):
        return 'Clean:\tMojibake:\tfound a mojibake'

    def run(self, line):
        cleaned_line = fix_encoding(line)
        return self.get_result(line, cleaned_line)


class NewlineModule(ModifyModule):
    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='newline',
            help_str="Enables removing newline characters ('\\r' and '\\n') from end and beginning of lines.")

    def debug_str(self):
        return 'Clean:\tNewline:\tfound a mojibake'

    def run(self, line):
        cleaned_line = line.strip('\r\n')
        return self.get_result(line, cleaned_line)



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