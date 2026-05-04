from .add import AddModule
from ..base import *

class FirstUpperModule(AddModule):

    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='add-first-upper',
            help_str='If a line does not contain a capital letter this will add the capital variant.')

    def run(self, line):
        # TODO: Does this extra variable add any meaningful execution time or memory usage?
        add_line = line.capitalize()
        return self.get_result(line, add_line)

# Might be confused with LowercaseModule...
class LowerModule(AddModule):
    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='add-lower',
            help_str='If a line contains a capital letter this will add the lowercase variant.')

    def run(self, line):
        add_line = line.lower()
        return self.get_result(line, add_line)

class TitleCase(AddModule):
    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='add-title-case',
            help_str='Add a line with every word capitalized.')

    def run(self, line):
        add_line = line.title()
        return self.get_result(line, add_line)