from re import split as re_split

from ..base import *
from .add import AddModule


class SplitModule(AddModule):
    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='add-split',
            help_str="Split on known characters like '-' and '.'")

    def run(self, line):
        punctuation = (' ', '-', r'\.')
        for p in punctuation:
            if p in line:
                # Why only if len(piece) > 1?
                components =  [piece for piece in re_split('|'.join(punctuation), line) if len(piece) > 1]
                return Result(status=True, msg=self.debug_str, add=components)
        return Result(status=False, msg=None)

class WithoutPunctuationModule(AddModule, ConfigModule):
    # This is related to PunctuationModule in a way... Can we link these?

    def set_configs(self, config):
        self.add_config('punctuation', config.punctuation)
    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='add-without-punctuation',
            help_str='If a line contains punctuation, a variant will be added without punctuation.')

    def run(self, line):
        cleaned_line = line.translate(str.maketrans('', '', self.get_config('punctuation')))
        return self.get_result(line, cleaned_line)