# - Remove module -
# Remove modules can remove parts of a line.
# These take a line as input, possibly with an argument.
# The module should return a bool result, a str out_line and a str log
# result is False if nothing was changed.
# out_line is the result of the operation
# log is a debug string which can be None. Logged when result is True (something changed)
from ..base import *

# Functionality-wise, a remove module is just a modify module.
# We still create a different abstract module class to separate this in a different help category, as well as different debug string.
class RemoveModule(Module):
    @staticmethod
    def get_pipeline_position():
        return PipelinePosition.AFTER_ENCODE

    def handle(self, result):
        return Actions(
            update=result.update,
            debug_str=result.msg,
        )

    @property
    def debug_str(self):
        return 'removed part of line'

    def get_result(self, line, cleaned_line):
        if line != cleaned_line:
            return Result(status=True, msg=self.debug_str, update=cleaned_line)
        return Result(status=False, msg=None)