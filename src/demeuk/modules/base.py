from abc import ABC, abstractmethod
from typing import NamedTuple, List

from re import search

from transliterate import translit


# Result of module.run
class Result(NamedTuple):
    status: bool
    debug_str: str | None
    add: str | list | None = None
    update : str | None = None


# NB: If you implement a standard module, you should not need to worry about this!
# Result of module.handle, these can perform an action
class Actions(NamedTuple):
    # Stop further demeuking if this is true
    stop: bool = False
    # Add lines to work queue
    add: list | None = None
    # Update line
    update: str | None = None
    # Log this string if not None
    log_str: str | None = None
    # Log this string if not None and --debug
    debug_str: str | None = None
    # Log for all added line is not None and --debug
    debug_add_str: str | None = None


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

    @abstractmethod
    def handle(self, result):
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

    def handle(self, result):
        return Actions(
            # If a check module is tripped, don't need to check anymore.
            stop=True,
            log_str=result.debug_str # Always log
        )




class AddModule(Module):
    @staticmethod
    def get_parser_group():
        return 'add'

    def handle(self, result):
        # Add either a string or list of strings to the queue
        if isinstance(result.add, list):
            add_list = result.add
        else:
            add_list = [result.add]
        return Actions(
            add=add_list,
            debug_add_str=result.debug_str
        )

class ModifyModule(Module):
    @staticmethod
    def get_parser_group():
        return 'modify'

    def handle(self, result):
        return Actions(
            update=result.update,
            debug_str=result.debug_str,
        )

    def get_result(self, line, cleaned_line):
        if line != cleaned_line:
            return Result(status=True, debug_str=self.debug_str(), update=cleaned_line)
        return Result(status=False, debug_str=None)

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
    def get_help_info():
        return HelpInfoParam(
            option='check-ending-with',
            help_str='Drop lines ending with string, can be multiple strings. Specify multiple with a comma-separated list.',
            metavar='<string>',
            param_type=str)

    def debug_str(self):
        return f'Check ending with; Dropped line because {self._param} found'

    def run(self, line) -> Result:
        for string in self._param.split(','):
            if line.endswith(string):
                return Result(status=True, debug_str=self.debug_str())
        return Result(status=False, debug_str=None)

class FirstUpperAddModule(AddModule):

    @staticmethod
    def get_help_info() -> HelpInfo:
        return HelpInfo(
            option='add-first-upper',
            help_str='If a line does not contain a capital letter this will add the capital variant.'
        )

    def debug_str(self):
        return 'Add first upper: new line'

    def run(self, line):
        line_first_upper = line.capitalize()

        if line != line_first_upper:
            return Result(status=True, debug_str=self.debug_str(), add=line_first_upper)
        return Result(status=False, debug_str=None)

class CleanTrimModifyModule(ModifyModule):

    TRIM_BLOCKS = ('\\\\n', '\\\\r', '\\n', '\\r', '<br>', '<br />')

    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='trim',
            help_str="Remove whitespace from beginning and end of line. Whitespace detected is '\\\\n', '\\\\r', '\\n', '\r', '<br>' and '<br />'."
        )

    def debug_str(self):
        return 'Clean Trim; found trim sequence'

    def run(self, line):
        cleaned_line = line
        # Ensure removal of duplicated blocks
        while True:
            has_match = False
            for x in self.TRIM_BLOCKS:
                if cleaned_line.startswith(x):
                    cleaned_line = cleaned_line[len(x):]
                    has_match = True

                if cleaned_line.endswith(x):
                    cleaned_line = cleaned_line[:-len(x)]
                    has_match = True

            if not has_match:
                break

        return self.get_result(line, cleaned_line)

# TODO add argparse thing where option can only take certain arguments
class TransliterateModifyModule(ModifyModule, ParamModule):
    @staticmethod
    def get_help_info():
        return HelpInfoParam(
            option='transliterate',
            help_str="Transliterate a string, for example 'ipsum' becomes 'իպսում'. The following languages are supported: ka, sr, l1, ru, mn, uk, mk, el, hy and bg.",
            metavar='<language>',
            param_type=str)

    def debug_str(self):
        return 'Clean transliterate; transliterated'

    def run(self, line):
        # TODO ipsum is not transliterated to ... because it is reversed. Other way around?
        cleaned_line = translit(line, self._param, reversed=True)

        return self.get_result(line, cleaned_line)
