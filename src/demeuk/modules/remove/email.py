from re import search, sub

from ..base import *
from .remove import RemoveModule


# EmailModule already exists as a check module...
# TODO should we capture the module type in the name? (CheckEmailModule)
class RemoveEmailModule(RemoveModule):

    # This is now in two places. Delegate this to a 'constants.py' or 'regexes.py' file?
    # Probably better, as this is not a 'config' or parameter about the module itself
    EMAIL_REGEX = '.{1,64}@([a-zA-Z0-9_-]{1,63}\\.){1,3}[a-zA-Z]{2,6}'

    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='remove-email',
            help_str="Enable email filter, this will catch strings like '1238661:test@example.com:password'.")

    def run(self, line):
        if '@' in line:
            if search(f'{self.EMAIL_REGEX}(:|;)', line):
                result_line = sub(f'{self.EMAIL_REGEX}(:|;)', '', line)
                return Result(status=True, msg=self.debug_str, update=result_line)
        return RESULT_NEXT