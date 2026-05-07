from .check import CheckModule
from ..base import *

class StartingWithModule(CheckModule, ParamModule):
    @staticmethod
    def get_help_info():
        return HelpInfoParam(
            option='check-starting-with',
            help_str='Drop lines starting with a string, specify multiple with comma-separated list.',
            metavar='<string>',
            param_type=str)

    def run(self, line):
        for substr in self.param.split(','):
            if line.startswith(substr):
                return self.stop
        return result_next

class EndingWithModule(CheckModule, ParamModule):
    @staticmethod
    def get_help_info():
        return HelpInfoParam(
            option='check-ending-with',
            help_str='Drop lines ending with a string, specify multiple with comma-separated list.',
            metavar='<string>',
            param_type=str)

    def run(self, line):
        for substr in self.param.split(','):
            if line.endswith(substr):
                return self.stop
        return result_next

class ContainsModule(CheckModule, ParamModule):
    @staticmethod
    def get_help_info():
        return HelpInfoParam(
            option='check-contains',
            help_str='Drop lines containing a string, specify multiple with comma-separated list.',
            metavar='<string>',
            param_type=str)

    def run(self, line):
        for substr in self.param.split(','):
            if substr in line:
                return self.stop
        return result_next
