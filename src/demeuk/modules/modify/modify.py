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