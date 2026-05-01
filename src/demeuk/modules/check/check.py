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



class ControlCharModule(CheckModule):

    def __init__(self):
        self.cc_found = None

    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='check-controlchar',
            help_str='Drop lines containing control characters.')

    def run(self, line) -> Result:
        for c in line:
            # https://en.wikipedia.org/wiki/Unicode_character_property#General_Category
            # Characters (they have meaning):
            # Cc -> Control Char (End of stream)
            # Cf -> Control flow (right to left)
            # Non chars:
            # Cn -> Not assigned
            # Co -> Private use
            # Cs -> Surrogate
            if category(c) in ['Cc', 'Cf', 'Cn', 'Co', 'Cs']:
                self.cc_found = c
                return Result(status=True, msg=self.debug_str)
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
        for string in self._param.split(','):
            if line.endswith(string):
                return Result(status=True, msg=self.debug_str)
        return Result(status=False, msg=None)

def contains_at_least(line, bound, char_property):
    """Check if the line contains at least `bound` characters with given property.

    Params:
        line (unicode)
        bound (int)
        char_property (str -> bool)

    Returns:
        true if at least `bound` characters match
        false otherwise
    """
    if bound == 0:
        return True

    count = 0
    for char in line:
        if char_property(char):
            count += 1
            if count >= bound:
                return True
    return False


def check_min_digits(line, n):
    if contains_at_least(line, n, str.isdigit):
        return False, None
    return True, f'Check_min_digits; dropped line because it contains less than {n} digits'


def check_min_uppercase(line, n):
    if contains_at_least(line, n, str.isupper):
        return False, None
    return True, f'Check_min_uppercase; dropped line because it contains less than {n} uppercase characters'


def check_min_specials(line, n):
    if contains_at_least(line, n, lambda c: not c.isalnum() and not c.isspace()):
        return False, None
    return True, f'Check_min_specials; dropped line because it contains less than {n} special characters'


def contains_at_most(line, bound, char_property):
    """Check if the line contains at most `bound` characters with given property.

    Params:
        line (unicode)
        bound (int)
        char_property (str -> bool)

    Returns:
        true if at most `bound` characters match
        false otherwise
    """
    count = 0
    for char in line:
        if char_property(char):
            count += 1
            if count > bound:
                return False
    return True


def check_max_digits(line, n):
    if contains_at_most(line, n, str.isdigit):
        return False, None
    return True, f'Check_max_digits; dropped line because it contains more than {n} digits'


def check_max_uppercase(line, n):
    if contains_at_most(line, n, str.isupper):
        return False, None
    return True, f'Check_max_uppercase; dropped line because it contains more than {n} uppercase characters'


def check_max_specials(line, n):
    if contains_at_most(line, n, lambda c: not c.isalnum() and not c.isspace()):
        return False, None
    return True, f'Check_max_specials; dropped line because it contains more than {n} special characters'


def check_controlchar(line):
    """Detects control chars, returns False when detected

    Params:
        line (Unicode)

    Returns:
        Status, String
    """
    for c in line:
        # https://en.wikipedia.org/wiki/Unicode_character_property#General_Category
        # Characters (they have meaning):
        # Cc -> Control Char (End of stream)
        # Cf -> Control flow (right to left)
        # Non chars:
        # Cn -> Not assigned
        # Co -> Private use
        # Cs -> Surrogate
        if category(c) in ['Cc', 'Cf', 'Cn', 'Co', 'Cs']:
            return True, f'Check_controlchar; found controlchar {c!r}'
    return False, None


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


def check_length(line, min=0, max=0):
    """Does a length check on the line

    Params:
        line (unicode)
        min (int)
        max (int)

    Returns:
        true if length is ok
    """
    status = True
    if min and status:
        status = len(line) >= min
    if max and status:
        status = len(line) < max
    return status


def check_min_length(line, n):
    if check_length(line, min=n):
        return False, None
    return True, f'Check_min_length; dropped line because length is less than {n}'


def check_max_length(line, n):
    if check_length(line, max=n):
        return False, None
    return True, f'Check_max_length; dropped line because length is more than {n}'


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


def check_character(line, character):
    """Checks if a line contains a specific character

    Params:
        line (unicode)

    Returns:
        true if line does contain the specific character

    """
    if character in line:
        return True
    else:
        return False


def check_replacement_character(line):
    if check_character(line, '�'):
        return True, 'Check_replacement_character; dropped line because "�" found'
    else:
        return False, None


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


def check_empty_line(line):
    """Checks if a line is empty or only contains whitespace chars

    Params:
        line (unicode)

    Returns:
        true of line is empty or only contains whitespace chars
    """
    if line == '' or line.isspace():
        return True, 'Check_empty_line; dropped line because is empty or only contains whitespace'
    return False, None
