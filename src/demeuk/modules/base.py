from abc import ABC, abstractmethod
from enum import Enum
from typing import NamedTuple


"""
This module contains the abstract base versions of demeuk modules, and some auxiliary help classes.
"""

# Result of module.run
class Result(NamedTuple):
    """
    The result of a module run() on a single line

    status: If this is True, some action needs to be performed. If this is false, continue to the next module.
    msg: A log or debug string
    add: Lines to add to the demeuk queue
    update: Change this line for future modules
    """
    status: bool
    msg: str | None
    add: str | bytes | list | None = None
    update: str | bytes | None = None

# Class (namedtuple/dataclass) creation is slow!
# For the results we use often, create them once and use them everywhere

# This result can be used if you want to continue to the next line, and not take any action
RESULT_NEXT=Result(status=False, msg=None)

# Result of module.handle, these can perform an action
# Note that we expect almost all of our input lines to return a Result with status=False, so almost none will go through
# to the handle phase. Therefore we don't reuse our Actions objects, even though they are slow to create.
class Actions(NamedTuple):
    """
    The result of a modules handle(), run on a Result when its status is True. These encode information on
    control flow and the actions to take after a module is tripped. Multiple actions can be set.
    If an attribute is not None, the corresponding action will be performed.

    stop: If True, don't do any more demeuking on this line and do not include it in the results.
    add: A list of lines to add to the work queue
    update: Update the current line to this string
    do_not_re_encode: A flag for use in combination with add. When set, we add back a byte sequence instead of a string into the queue
    log_str: When set, log a string.
    debug_str: When set, log a string if --debug is set.
    debug_add_str: For use in combination with add. When set, log a string for every added line if --debug is set.
    """
    stop: bool = False
    add: list | None = None
    update: str | None = None
    do_not_re_encode: bool = False
    log_str: str | None = None
    debug_str: str | None = None
    debug_add_str: str | None = None


class HelpInfo(NamedTuple):
    """
    Tuple containing 'help info' about a module which does not take a parameter.

    option: A string or list of strings of command-line names. These should not start with dashes.
    help_str: The explainer string for this module for use in demeuk -h.
    """
    option: str | list[str]
    help_str: str


class HelpInfoParam(NamedTuple):
    """
    Tuple containing 'help info' about a module which does take a parameter.

    option: A string or list of strings of command-line names. These should not start with dashes.
    help_str: The explainer string for this module for use in demeuk -h.
    param_type: The type of the parametere this module expects
    metavar: The name by which the parameter can be reference in the help string, for example '<string>'
    """
    option: str | list[str]
    help_str: str
    param_type: type
    metavar: str


# An enum describing the different positions which a module can be in, depending on how they act on types
PipelinePosition = Enum('PipelinePosition', [
    ('BEFORE_ENCODE', 0),   # Modules which act on bytes
    ('ENCODE', 1),          # Modules which turn bytes into strings
    ('AFTER_ENCODE', 2)])        # Modules which act on strings



class Module(ABC):
    """
    The abstract base class for a demeuk module. If you want to add a new module to demeuk, you should probably not
    implement this class unless you know what you're doing. You should instead implement one of:
    AddModule, CheckModule, ModifyModule, RemoveModule or MacroModule.
    """
    @staticmethod
    @abstractmethod
    def get_help_info() -> HelpInfo | HelpInfoParam:
        """
        Return either a HelpInfo or HelpInfoParam tuple, for the command-line option and the info displayed when running demeuk -h.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def debug_str(self) -> str:
        """
        Returns a small debug string describing the action of a module. For example: 'dropped line', 'modified line'.
        NB: When logging with --debug, the class name is logged, along with the debug string and the line in question.
        """
        raise NotImplementedError

    @abstractmethod
    def run(self, line) -> Result:
        """
        Run the module on a line. Note that this module is runs for every word in the word list!
        :param line: The line on which the module runs
        :return: A Result object.
        """
        raise NotImplementedError

    @abstractmethod
    def handle(self, result):
        """
        Handle the result of Module.run(). Unless you are implementing a new category of module, you should use the
        implementation of AddModule, CheckModule, etc.
        :param result: The result of Module.run().
        :return: An Actions object containing the actions to perform.
        """
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def get_pipeline_position() -> PipelinePosition:
        """
        Here you can set where in the pipeline this module should be placed. If it takes a string and spits out a string,
        this should be PipelinePosition.AFTER_ENCODE.
        """
        raise NotImplementedError


class ParamModule(Module):
    """
    The abstract base class for a demeuk module which takes a parameter.
    If you implement this class, you need to supply the parameter to the constructor, which can then be recalled by accessing the class property param.
    """
    def __init__(self, parameter):
        self._param = self.get_help_info().param_type(parameter)

    @staticmethod
    @abstractmethod
    def get_help_info() -> HelpInfoParam:
        """
        Return a HelpInfoParam tuple containing the help info for this module.
        """
        raise NotImplementedError

    @property
    def param(self):
        return self._param

    @param.setter
    def param(self, value):
        self._param = self.get_help_info().param_type(value)

# A module with some configuration.
class ConfigModule(Module):
    """
    The abstract base class for a demeuk module which depends on configuration.
    If you implement this class, you need to add key-value pairs of config values in set_configs, which can then be accessed by get_config.
    This can be used to let some global config option influence multiple modules at the same time.
    """
    def __init__(self):
        self._config = {}

    @abstractmethod
    def set_configs(self, config):
        """
        Set config values for this module. You can use add_config in this function to actually store the values.
        :param config: The Config object obtained from the parsed command-line arguments.
        """
        raise NotImplementedError

    def add_config(self, key, value):
        """
        Store a key-value pair in the config dict for this module.
        :param key: The key
        :param value: The value
        """
        self._config[key] = value

    def get_config(self, key):
        """
        Retrieve a config value from the config dict
        :param key: The key
        :return: The associated config value
        """
        return self._config[key]














