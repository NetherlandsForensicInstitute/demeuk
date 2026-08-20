
from ..base import *


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
        """
        Handle the result of AddModule.run(). Expects a Result with the add field set and a debug message, as returned from get_result().

        :param result: Result of an AddModule run()
        :type result: Result
        :return: Actions object which adds the line(s) to the queue.
        """
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
        :type line: str
        :param added_line: The line to add
        :type added_line: str
        :return: The result to return from run()
        """
        if line != added_line:
            return Result(status=True, msg=self.debug_str, add=added_line)
        return RESULT_NEXT