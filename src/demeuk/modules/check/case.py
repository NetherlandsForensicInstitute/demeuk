from .check import CheckModule
from ..base import *

class CaseModule(CheckModule):

    ignored_chars = [' ', "'", '-']

    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='check-case',
            help_str='Drop lines where the uppercase line is not equal to the lowercase line.')

    def run(self, line):
        for c in line:
            c = str(c)
            if c.lower() == c.upper():
                if c in self.ignored_chars:
                    continue
                else:
                    return self.stop
        return RESULT_NEXT


