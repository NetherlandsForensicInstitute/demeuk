from ..base import *
from .check import CheckModule


# Maybe add a BoundsCheckModule which automatically creates min/max versions based on a lambda?

# TODO strange bug where some test fail and some pass some of the time...?
# investigate more.


class MinLengthModule(CheckModule, ParamModule):
    @staticmethod
    def get_help_info():
        return HelpInfoParam(
            option='check-min-length',
            help_str='Require that entries contain at least <N> characters.',
            metavar='<N>',
            param_type=int)

    def run(self, line):
        if len(line) < self.param:
            return self.stop
        return self.next


class MaxLengthModule(CheckModule, ParamModule):
    @staticmethod
    def get_help_info():
        return HelpInfoParam(
            option='check-max-length',
            help_str='Require that entries contain at most <N> characters.',
            metavar='<N>',
            param_type=int)

    def run(self, line):
        if len(line) > self.param:
            return self.stop
        return self.next

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
            option='check-min-special',
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
            option='check-max-special',
            help_str='Require that entries contain at most <N> special characters.',
            metavar='<N>',
            param_type=int)

    def run(self, line):
        if sum([not c.isalnum() and not c.isspace() for c in line]) > self.param:
            return self.stop
        return self.next
