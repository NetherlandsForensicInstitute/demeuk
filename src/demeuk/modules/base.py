from abc import ABC, abstractmethod
from typing import NamedTuple, List

from re import search


class Result(NamedTuple):
    status: bool
    debug_str: str | None

class HelpInfo(NamedTuple):
    option: str | list[str]
    help_str: str

class HelpInfoParam(NamedTuple):
    option: str | list[str]
    help_str: str
    param_type: type
    metavar: str



class Module(ABC):
    @staticmethod
    @abstractmethod
    def get_help_info() -> HelpInfo | HelpInfoParam:
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def get_parser_group() -> str:
        raise NotImplementedError

    @property
    @abstractmethod
    def debug_str(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def run(self, line) -> Result:
        raise NotImplementedError

# Has a parameter
class ParamModule(Module):
    def __init__(self, parameter):
        self._param = parameter

    @staticmethod
    @abstractmethod
    def get_help_info() -> HelpInfoParam:
        raise NotImplementedError

    @property
    def param(self):
        return self._param

    @param.setter
    def param(self, value):
        self._param = value




# Some module implementations for testing

class CheckModule(Module):

    @staticmethod
    def get_parser_group():
        return 'check'

    @abstractmethod
    def run(self, line) -> Result:
        raise NotImplementedError

EMAIL_REGEX = '.{1,64}@([a-zA-Z0-9_-]{1,63}\\.){1,3}[a-zA-Z]{2,6}'

class EmailCheckModule(CheckModule):

    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='check-email',
            help_str='Drop lines containing e-mail addresses.',
        )


    def debug_str(self):
        return 'Check email: Dropped line because found email'

    def run(self, line) -> Result:
        if search(EMAIL_REGEX, line):
            return Result(status=True, debug_str=self.debug_str())
        return Result(status=False, debug_str=None)

class EndingWithCheckModule(CheckModule, ParamModule):

    @staticmethod
    def get_help_info() -> HelpInfoParam:
        return HelpInfoParam(
            option='check-ending-with',
            help_str='Drop lines ending with string, can be multiple strings. Specify multiple with a comma-separated list.',
            metavar='<string>',
            param_type=str)

    def debug_str(self):
        return f'Check ending with; Dropped line because {self._param} found'

    def run(self, line) -> Result:
        for string in self._param.split(','):
            if line.endswitch(string):
                return Result(status=True, debug_str=self.debug_str())
        return Result(status=False, debug_str=None)