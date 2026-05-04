from ftfy.fixes import fix_latin_ligatures

from .add import AddModule
from ..base import *

class LatinLigaturesModule(AddModule):
    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='add-latin-ligatures',
            help_str='If a line contains ligatures of Latin letter (such as ij), the line is correct but the original line containing the ligatures is also added to output.')

    def run(self, line):
        add_line = fix_latin_ligatures(line)
        return self.get_result(line, add_line)