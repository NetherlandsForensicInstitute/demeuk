from ..base import *
from .add import AddModule


# Looks very mych like UmlautModule (ModifyModule).
# Why do we need --umlaut AND --add-umlaut?
class UmlautAddModule(AddModule):
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
            option='add-umlaut',
            help_str='Add line with fixed umlauting (o", U" to ö, Ü)')

    def run(self, line):
        add_line = line
        for pattern, replacement in self.umlaut_dict.items():
            add_line = add_line.replace(pattern, replacement)

        return self.get_result(line, add_line)


