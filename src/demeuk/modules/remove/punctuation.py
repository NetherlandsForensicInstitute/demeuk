from ..base import *
from .remove import RemoveModule


class StripPunctuationModule(RemoveModule, ConfigModule):
    def set_configs(self, config):
        self.add_config('punctuation', config.punctuation)

    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='remove-strip-punctuation',
            help_str='Remove starting and trailing punctuation.')

    def run(self, line):
        return_line = line.strip(self.get_config('punctuation'))
        return self.get_result(line, return_line)

class PunctuationModule(RemoveModule, ConfigModule):
    def set_configs(self, config):
        self.add_config('punctuation', config.punctuation)

    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='remove-punctuation',
            help_str='Remove all punctuation from a line.')

    def run(self, line):
        return_line = line.translate(str.maketrans('', '', self.get_config('punctuation')))
        return self.get_result(line, return_line)
