# - Check module -
# Check modules check some property of a line.
# These should take a line as input, possibly with one argument.
# The module should return a bool result and a str log
# result is True if it needs to be dropped, so False if it is included in the list.
# log is a string which can be None. It is logged when result if True (line dropped)

# TODO: change docstrings, return values are wrong.

from re import search
from unicodedata import category

from ..base import *

# Maybe add shortcut Result object ResultPass and ResultFail or something?
class CheckModule(Module):

    @staticmethod
    def get_pipeline_position():
        return PipelinePosition.AFTER_ENCODE

    @property
    def debug_str(self) -> str:
        return f'dropped line'

    @abstractmethod
    def run(self, line) -> Result:
        raise NotImplementedError

    def handle(self, result):
        return Actions(
            # If a check module is tripped, don't need to run any more modules.
            stop=True,
            log_str=result.msg  # Always log checks
        )

    # Standard results for check modules:
    # Stop prints a message to the logs, and does not process the line any further
    @property
    def stop(self) -> Result:
        return Result(status=True, msg=self.debug_str)

    # Next does nothing and continues to the next line
    @property
    def next(self) -> Result:
        return Result(status=False, msg=None)





class EndingWithCheckModule(CheckModule, ParamModule):

    @staticmethod
    def get_help_info():
        return HelpInfoParam(
            option='check-ending-with',
            help_str='Drop lines ending with string, can be multiple strings. Specify multiple with a comma-separated list.',
            metavar='<string>',
            param_type=str)

    def run(self, line) -> Result:
        for string in self.param.split(','):
            if line.endswith(string):
                return Result(status=True, msg=self.debug_str)
        return Result(status=False, msg=None)


def check_case(line, ignored_chars=(' ', "'", '-')):
    """Checks if an uppercase line is equal to a lowercase line.

    Param:
        line (unicode)
        ignored_chars list(string)

    Returns:
        true if uppercase line is equal to uppercase line
    """
    for c in line:
        c = str(c)
        if c.lower() == c.upper():
            if c in ignored_chars:
                continue
            else:
                return True, f'Check_case; dropped line because of {c}'
    return False, None


def check_non_ascii(line):
    """Checks if a line contains a non ascii chars

    Params:
        line (unicode)

    Returns:
        true if line does not contain non ascii chars
    """
    try:
        line.encode('ascii')
        return False, None
    except UnicodeEncodeError:
        return True, 'Check_non_ascii; dropped line because non ascii char found'



def check_starting_with(line, strings):
    """Checks if a line start with a specific strings

    Params:
        line (unicode)
        strings[str]

    Returns:
        true if line does start with one of the strings

    """
    for string in strings.split(','):
        if line.startswith(string):
            return True, f'Check_starting_with; dropped line because {string} found'
    return False, None


def check_ending_with(line, strings):
    """Checks if a line ends with specific strings

    Params:
        line (unicode)
        strings[str]

    Returns:
        true if line does end with one of the strings

    """
    for string in strings.split(','):
        if line.endswith(string):
            return True, f'Check_ending_with; dropped line because {string} found'
    return False, None


def check_contains(line, strings):
    """Checks if a line does not contain specific strings

    Params:
        line (unicode)
        strings[str]

    Returns:
        true if line does contain any one of the strings

    """
    for string in strings.split(','):
        if string in line:
            return True, f'Check-contains; dropped line because {string} found'
    return False, None