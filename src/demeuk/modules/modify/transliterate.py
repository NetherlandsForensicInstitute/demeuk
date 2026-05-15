from transliterate import translit
from ..base import *
from .modify import ModifyModule


class TransliterateModule(ModifyModule, ParamModule):
    @staticmethod
    def get_help_info():
        return HelpInfoParam(
            option='transliterate',
            help_str="Transliterate a string, for example 'իպսում' becomes 'ipsum'  The following languages are supported: ka, sr, l1, ru, mn, uk, mk, el, hy and bg.",
            metavar='<language>',
            param_type=str)

    def run(self, line):
        cleaned_line = translit(line, self._param, reversed=True)

        return self.get_result(line, cleaned_line)
