from re import search
from unicodedata import category

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
        return f'dropped line'

    def handle(self, result):
        return Actions(
            # If a check module is tripped, don't need to run any more modules.
            stop=True,
            log_str=result.msg)  # Always log if this happens

    # Return this to stop further processing.
    @property
    def stop(self) -> Result:
        return Result(status=True, msg=self.debug_str)

    # Return this to continue to the next module.
    @property
    def next(self) -> Result:
        # Creating a Result is slow so we reference one instance.
        # For stop, this is not needed as we expect almost all lines to return next.
        return RESULT_NEXT
