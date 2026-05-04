from ftfy import fix_encoding
from unidecode import unidecode

from .modify import ModifyModule
from ..base import *

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
        cleaned_line = fix_encoding(line)
        return self.get_result(line, cleaned_line)
