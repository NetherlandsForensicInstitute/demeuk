# - Modify module -
# Modify modules modify a line
# Module signature is the same as that of a remove module
from ..base import *

class ModifyModule(Module):

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
        return 'modified line'

    def get_result(self, line, cleaned_line):
        if line != cleaned_line:
            return Result(status=True, msg=self.debug_str, update=cleaned_line)
        return Result(status=False, msg=None)