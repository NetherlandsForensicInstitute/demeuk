from .check import CheckModule
from ..base import *

# Maybe add a BoundsCheckModule which automatically creates min/max versions?

# TODO strange bug where some test fail and some pass some of the time...?
# investigate more.

class MinDigitsModule(CheckModule, ParamModule):
    @staticmethod
    def get_help_info():
        return HelpInfoParam(
            option='check-min-digits',
            help_str='Require that entries contain at least <N> digits.',
            metavar='<N>',
            param_type=int)

    def run(self, line):
        if sum([c.isdigit() for c in line]) < self.param:
            return self.stop
        return self.next

class MaxDigitsModule(CheckModule, ParamModule):
    @staticmethod
    def get_help_info():
        return HelpInfoParam(
            option='check-max-digits',
            help_str='Require that entries contain at most <N> digits.',
            metavar='<N>',
            param_type=int)

    def run(self, line):
        if sum([c.isdigit() for c in line]) > self.param:
            return self.stop
        return self.next

class MinUppercaseModule(CheckModule, ParamModule):
    @staticmethod
    def get_help_info():
        return HelpInfoParam(
            option='check-min-uppercase',
            help_str='Require that entries contain at least <N> uppercase characters.',
            metavar='<N>',
            param_type=int)

    def run(self, line):
        if sum([c.isupper() for c in line]) < self.param:
            return self.stop
        return self.next

class MaxUppercaseModule(CheckModule, ParamModule):
    @staticmethod
    def get_help_info():
        return HelpInfoParam(
            option='check-max-uppercase',
            help_str='Require that entries contain at most <N> uppercase characters.',
            metavar='<N>',
            param_type=int)

    def run(self, line):
        if sum([c.isupper() for c in line]) > self.param:
            return self.stop
        return self.next

class MinSpecialsModule(CheckModule, ParamModule):
    @staticmethod
    def get_help_info():
        return HelpInfoParam(
            option='check-min-specials',
            help_str='Require that entries contain at least <N> special characters.',
            metavar='<N>',
            param_type=int)

    def run(self, line):
        if sum([not c.isalnum() and not c.isspace() for c in line]) < self.param:
            return self.stop
        return self.next

class MaxSpecialsModule(CheckModule, ParamModule):
    @staticmethod
    def get_help_info():
        return HelpInfoParam(
            option='check-max-specials',
            help_str='Require that entries contain at most <N> special characters.',
            metavar='<N>',
            param_type=int)

    def run(self, line):
        if sum([not c.isalnum() and not c.isspace() for c in line]) > self.param:
            return self.stop
        return self.next
