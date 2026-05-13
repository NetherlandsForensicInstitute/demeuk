from ..base import *


# Functionality-wise, a remove module is just a modify module.
# We still create a different abstract module class to separate this in a different help category, as well as different debug string.
class RemoveModule(Module):
    """
    The abstract base class for remove modules.
    Remove modules can remove certain parts of a line.
    """
    @staticmethod
    def get_pipeline_position():
        return PipelinePosition.AFTER_ENCODE

    def handle(self, result):
        """
        Handle the result of RemoveModule.run(). Expects a result with the update field set and a debug message.

        :param result: Result of RemoveModule.run()
        :type result: Result
        :return: Actions object which updates the line
        """
        return Actions(
            update=result.update,
            debug_str=result.msg)

    @property
    def debug_str(self):
        return 'removed part of line'

    def get_result(self, line, cleaned_line):
        """
        Utility function to get the appropriate Result object when modifying a line, to return from run().
        Checks if the new candidate is equal to the input line and only updates it if they differ.

        :param line: The input line
        :type line: str
        :param cleaned_line: The modified line
        :type cleaned_line: str
        :return: The result to return from run()
        """
        if line != cleaned_line:
            return Result(status=True, msg=self.debug_str, update=cleaned_line)
        return RESULT_NEXT