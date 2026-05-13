from ..base import *


class ModifyModule(Module):
    """
    The abstract base class for modify modules.
    Modify modules replace the current line by a new line.
    Modify modules can be used as a preprocessing step, for example to fix encoding mistakes.
    Modify modules can also be used to standardize the contents of a corpus, for example to make everything lowercase.
    """

    @staticmethod
    def get_pipeline_position():
        return PipelinePosition.AFTER_ENCODE

    def handle(self, result):
        return Actions(
            # Update the line in the queue
            update=result.update,
            debug_str=result.msg) # Only log if --debug is set.

    @property
    def debug_str(self):
        return 'modified line'

    def get_result(self, line, cleaned_line):
        """
        Utility function to get the appropriate Result object when modifying a line, to return from run().
        Checks if the new candidate is equal to the input line and only updates it if they differ.
        :param line: The input line
        :param cleaned_line: The modified line
        :return: The result to return from run()
        """
        if line != cleaned_line:
            return Result(status=True, msg=self.debug_str, update=cleaned_line)
        return RESULT_NEXT