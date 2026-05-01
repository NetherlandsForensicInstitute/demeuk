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
        return self.next
