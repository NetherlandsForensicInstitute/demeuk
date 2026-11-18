from unicodedata import category

from ..base import *
from .check import CheckModule


class ReplacementCharModule(CheckModule):
    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='check-replacement-character',
            help_str="Drop lines containing replacement characters '�'.")

    def run(self, line) -> Result:
        if '�' in line:
            return self.stop
        return self.next

class ControlCharModule(CheckModule):

    IS_CONTROL_LOOKUP = bytes(
        category(chr(i))[0] == 'C' for i in range(0x110000)
    )

    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='check-controlchar',
            help_str='Drop lines containing control characters.')

    @staticmethod
    def is_controlchar(c):
        # Shortcut: If ascii, this is easily determined
        return ControlCharModule.IS_CONTROL_LOOKUP[ord(c)]

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
            if self.is_controlchar(c):
                return self.stop
        return self.next
