
from ..base import *


# Maybe add shortcut Result object ResultPass and ResultFail or something?
class CheckModule(Module):
    """
    The abstract base class for check modules.
    Check modules test a certain property, and can drop a line if this property is (not) met.
    """

    @staticmethod
    def get_pipeline_position():
        return PipelinePosition.AFTER_ENCODE

    @property
    def debug_str(self) -> str:
        return 'dropped line'

    def handle(self, result):
        """
        Handle the result of CheckModule.run().  Expects a result with a log message, like stop() or next().

        :param result: Result of a CheckModule run()
        :type result: Result
        :return: Actions object which stops further processing
        """
        return Actions(
            # If a check module is tripped, don't need to run any more modules.
            stop=True,
            log_str=result.msg)  # Always log if this happens

    @property
    def stop(self) -> Result:
        """
        Return this from run() to stop further processing

        :return: A Result object to pass to handle()
        """
        return Result(status=True, msg=self.debug_str)

    @property
    def next(self) -> Result:
        """
        Return this from run() to continue to the next module

        :return: A Result object to pass to handle()
        """
        # Creating a Result is slow so we reference one instance.
        # For stop, this is not needed as we expect almost all lines to return next.
        return RESULT_NEXT
