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
            log_str=result.msg)  # Always log checks

    # Stop prints a message to the logs, and does not process the line any further
    @property
    def stop(self) -> Result:
        return Result(status=True, msg=self.debug_str)
