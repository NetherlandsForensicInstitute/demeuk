from ..base import *


class MacroModule(Module):
    """
    The abstract base class for a macro module.
    Macro modules are modules which can invoke other modules.
    """

    @abstractmethod
    def get_submodules(self) -> List[Module]:
        """
        Determines what modules to add to the pipeline.
        :return: An ordered list of instances of modules to add to the pipeline.
        """
        raise NotImplementedError

    # By default, we assume that a macro module is only used as a collection of other modules.
    # We implement this here so that you can easily create a new macro module

    # However you can override these functions for custom behavior.
    def run(self, line):
        return RESULT_NEXT

    def handle(self, results):
        return Actions()

    @property
    def debug_str(self) -> str:
        return 'performed action'

    @staticmethod
    def get_pipeline_position():
        return PipelinePosition.AFTER_ENCODE



