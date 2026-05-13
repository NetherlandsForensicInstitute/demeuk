from ..base import *
from .check import CheckModule


# Name conflict with NonAsciiModule
class NonAsciiCheckModule(CheckModule):
    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='check-non-ascii',
            help_str='If a line contain a non ascii char e.g. ü or ç (everything outside ascii range) the line is dropped.')

    def run(self, line):
        try:
            line.encode('ascii')
            return self.next
        except UnicodeEncodeError:
            return self.stop