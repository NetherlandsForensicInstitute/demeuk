from re import compile as re_compile

from .modify import ModifyModule
from ..base import *

class HexModule(ModifyModule):

    HEX_REGEX = re_compile(r'^\$(?:HEX|hex)\[((?:[0-9a-fA-F]{2})+)\]$')


    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='hex',
            help_str='Replace lines like: $HEX[41424344] with ABCD.'
        )

    @property
    def debug_str(self) -> str:
        return 'replaced $HEX[], added to queue and quitting'

    def run(self, line):
        match = self.HEX_REGEX.search(line)
        if match:
            return Result(status=True, msg=self.debug_str, add=unhexlify(match.group(1)))
        return RESULT_NEXT

    def handle(self, result):
        return Actions(
            add=[result.add], # expects a list.
            debug_str=result.msg,
            stop=True,
            do_not_re_encode=True)