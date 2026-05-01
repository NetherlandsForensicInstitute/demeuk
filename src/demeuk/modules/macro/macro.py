from ..base import *

# Module which contains a list of other modules to enable.
# Can also include a "real" module with new functionaliry
class MacroModule(Module):

    @abstractmethod
    def get_submodules(self) -> List[Module]:
        raise NotImplementedError

    # By default, we assume that a macro module is only used as a collection of other modules.
    # We implement this here so that you can easily create a new macro module

    # However you can override these functions for custom behavior.
    def run(self, line):
        return Result(status=False, msg=None)

    def handle(self, results):
        return Actions()

    @property
    def debug_str(self) -> str:
        return f'performed action'

    @staticmethod
    def get_pipeline_position():
        return PipelinePosition.AFTER_ENCODE



