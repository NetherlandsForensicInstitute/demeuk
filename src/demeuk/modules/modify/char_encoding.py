from ftfy import fix_encoding
from unidecode import unidecode

from ..base import *
from .modify import ModifyModule


class NonAsciiModule(ModifyModule):
    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='non-ascii',
            help_str='Replace non-ASCII characters with an ASCII variant. For example, ü becomes u, ç becomes c.')

    def run(self, line):
        cleaned_line = unidecode(line)
        return self.get_result(line, cleaned_line)


class MojibakeModule(ModifyModule):
    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='mojibake',
            help_str='Fixes mojibakes, which means lines like SmˆrgÂs will be fixed to Smörgås.')

    def run(self, line):
        if not line.isascii():
            cleaned_line = fix_encoding(line)
            return self.get_result(line, cleaned_line)
        # If the line is ascii, it is not a mojibake.
        # Mojibake detection takes quite some time, so we pre-filtering with a C function (isascii)
        return RESULT_NEXT
