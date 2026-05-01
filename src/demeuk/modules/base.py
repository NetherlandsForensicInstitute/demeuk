from abc import ABC, abstractmethod
from binascii import unhexlify
from enum import Enum
from re import search, sub
from re import compile as re_compile
from typing import NamedTuple, List

from transliterate import translit


# Result of module.run
class Result(NamedTuple):
    status: bool
    msg: str | None
    add: str | bytes | list | None = None
    update: str | bytes | None = None


# NB: If you implement a standard module, you should not need to worry about this!
# Result of module.handle, these can perform an action
class Actions(NamedTuple):
    # Stop further demeuking if this is true
    stop: bool = False
    # Add lines to work queue
    add: list | None = None
    # Update line
    update: str | None = None
    # Add bytes back instead of re-encoding? (only used for --html)
    do_not_re_encode: bool = False
    # Log this string if not None
    log_str: str | None = None
    # Log this string if not None and --debug
    debug_str: str | None = None
    # Log for all added line is not None and --debug
    debug_add_str: str | None = None


class HelpInfo(NamedTuple):
    option: str | list[str]
    help_str: str


class HelpInfoParam(NamedTuple):
    option: str | list[str]
    help_str: str
    param_type: type
    metavar: str


PipelinePosition = Enum('PipelinePosition', [
    ('BEFORE_ENCODE', 0),   # Modules which act on bytes
    ('ENCODE', 1),          # Modules which turn bytes into strings
    ('AFTER_ENCODE', 2)])        # Modules which act on strings



class Module(ABC):
    @staticmethod
    @abstractmethod
    def get_help_info() -> HelpInfo | HelpInfoParam:
        raise NotImplementedError

    @property
    @abstractmethod
    def debug_str(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def run(self, line) -> Result:
        raise NotImplementedError

    @abstractmethod
    def handle(self, result):
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def get_pipeline_position() -> PipelinePosition:
        raise NotImplementedError


# Has a parameter
class ParamModule(Module):
    def __init__(self, parameter):
        self._param = parameter

    @staticmethod
    @abstractmethod
    def get_help_info() -> HelpInfoParam:
        raise NotImplementedError

    @property
    def param(self):
        return self._param

    @param.setter
    def param(self, value):
        self._param = value

# A module with some configuration.
class ConfigModule(Module):
    def __init__(self):
        self._config = {}

    @abstractmethod
    def set_configs(self, config):
        raise NotImplementedError

    def add_config(self, key, value):
        self._config[key] = value

    def get_config(self, key):
        return self._config[key]














