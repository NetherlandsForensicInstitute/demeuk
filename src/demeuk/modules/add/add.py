# - Add modules -
# Add modules take a line as input, and output either a list of lines or a single line
# which is to be added to the work queue.
# Input is a single str
# Output is either bool result, str out_line, str log OR:
# bool result, list[str] out_lines, str log.
# result should be true if it out_line or out_lines need to be added to the queue
from re import split as re_split
from string import punctuation as string_punctuation

from ..base import *

from ftfy.fixes import fix_latin_ligatures


# For certain string checks/operations, we maybe want to construct an Add, Remove and Modify(Clean) module in one go?
# For example umlauting
class AddModule(Module):
    @staticmethod
    def get_pipeline_position():
        return PipelinePosition.AFTER_ENCODE

    @property
    def debug_str(self) -> str:
        return 'added line'

    def handle(self, result):
        # Add either a string or list of strings to the queue
        if isinstance(result.add, list):
            add_list = result.add
        else:
            add_list = [result.add]
        return Actions(
            add=add_list,
            debug_add_str=result.msg)

    def get_result(self, line, added_line):
        if line != added_line:
            return Result(status=True, msg=self.debug_str, add=added_line)
        return RESULT_NEXT