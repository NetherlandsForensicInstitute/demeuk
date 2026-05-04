from .modify import ModifyModule
from ..base import *

class LowercaseModule(ModifyModule):
    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='lowercase',
            help_str="Replace line like 'This Test String' with 'this test string'.")

    def run(self, line):
        cleaned_line = line.lower()
        return self.get_result(line, cleaned_line)

class TitleCaseModule(ModifyModule):

    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='title-case',
            help_str="Replace line like 'this test string' with 'This Test String'.")

    def run(self, line):
        cleaned_line = line.title()
        return self.get_result(line, cleaned_line)