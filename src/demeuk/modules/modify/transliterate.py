from transliterate import translit
from ..base import *
from .modify import ModifyModule


# TODO add argparse thing where option can only take certain arguments
class TransliterateModule(ModifyModule, ParamModule):
    @staticmethod
    def get_help_info():
        return HelpInfoParam(
            option='transliterate',
            help_str="Transliterate a string, for example 'ipsum' becomes 'իպսում'. The following languages are supported: ka, sr, l1, ru, mn, uk, mk, el, hy and bg.",
            metavar='<language>',
            param_type=str)

    def run(self, line):
        # TODO ipsum is not transliterated to ... because it is reversed. Other way around?
        cleaned_line = translit(line, self._param, reversed=True)

        return self.get_result(line, cleaned_line)
