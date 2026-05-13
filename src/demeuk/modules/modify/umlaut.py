from demeuk.modules.base import *

from .modify import ModifyModule


class UmlautModule(ModifyModule):
    # Duplicated. Store somewhere else?
    umlaut_dict = {
        'a"': 'ä',
        'i"': 'ï',
        'o"': 'ö',
        'u"': 'ü',
        'e"': 'ë',
        'A"': 'Ä',
        'I"': 'Ï',
        'O"': 'Ö',
        'U"': 'Ü',
        'E"': 'Ë',
    }

    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='umlaut',
            help_str='Replace lines like ko"ffie with köffie')

    def run(self, line):
        cleaned_line = line
        for pattern, replacement in self.umlaut_dict.items():
            cleaned_line = cleaned_line.replace(pattern, replacement)

        return self.get_result(line, cleaned_line)