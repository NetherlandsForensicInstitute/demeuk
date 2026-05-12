from re import split as re_split
from string import punctuation as string_punctuation

from ..base import *

from ftfy.fixes import fix_latin_ligatures


# For certain string checks/operations, we maybe want to construct an Add, Remove and Modify(Clean) module in one go?
# For example umlauting
class AddModule(Module):
    """
    The abstract base class for add modules.
    Add modules can add variants of lines to the work queue
    """
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
        # Log a message for every added line if --debug is set.
        return Actions(
            add=add_list,
            debug_add_str=result.msg)

    def get_result(self, line, added_line):
        """
        Utility function to get the appropriate Result object when (possibly) adding one line, to return from run().
        Checks if the new candidate is equal to the input line and only adds it if they differ.
        :param line: The input line
        :param added_line: The line to add
        :return: The result to return from run()
        """
        if line != added_line:
            return Result(status=True, msg=self.debug_str, add=added_line)
        return RESULT_NEXT