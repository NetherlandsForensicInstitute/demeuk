from unicodedata import category

from .check import CheckModule
from ..base import *

class ReplacementCharModule(CheckModule):
    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='check-replacement-character',
            help_str="Drop lines containing replacement characters '�'.")

    def run(self, line) -> Result:
        if '�' in line:
            return self.stop
        return result_next

class ControlCharModule(CheckModule):

    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='check-controlchar',
            help_str='Drop lines containing control characters.')

    def run(self, line) -> Result:
        for c in line:
            # https://en.wikipedia.org/wiki/Unicode_character_property#General_Category
            # Characters (they have meaning):
            # Cc -> Control Char (End of stream)
            # Cf -> Control flow (right to left)
            # Non chars:
            # Cn -> Not assigned
            # Co -> Private use
            # Cs -> Surrogate
            if category(c) in ['Cc', 'Cf', 'Cn', 'Co', 'Cs']:
                return self.stop
        return result_next
