from .check import CheckModule
from ..base import *

class EmptyLineModule(CheckModule):
    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='check-empty-line',
            help_str='Drop lines that are empty or only contain whitespace character.')

    def run(self, line):
        if line == '' or line.isspace():
            return self.stop
        return result_next
