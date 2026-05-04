from .macro import MacroModule
from ..base import *

from ..modify.input_encode import EncodeModule
from ..modify.char_encoding import MojibakeModule
from ..modify.html import *
from ..modify.hex import HexModule
from ..modify.whitespace import NewlineModule
from ..check.regex import *
from ..check.character import *
from ..check.empty_line import EmptyLineModule

# NB: Macro module contains config module as submodule. So we pass the config on...
# Maybe not the best way? or not too bad...
class LeakModule(MacroModule, ConfigModule):
    def set_configs(self, config):
        # Store the entire config as config...
        self.add_config('config', config)

    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='leak',
            help_str='When set, demeuk will run the following modules: mojibake, encode, newline, check-controlchar. '
                     'This is recommended when working with leaks.'
        )

    def get_submodules(self):
        # We need to instantiate this explicitly because we want to pass config.
        encode_module = EncodeModule()
        encode_module.set_configs(self.get_config('config'))
        return [
            encode_module,
            MojibakeModule(),
            ControlCharModule(),
            NewlineModule(),
        ]

class LeakFullModule(MacroModule, ConfigModule):
    def set_configs(self, config):
        self.add_config('config', config)

    @staticmethod
    def get_help_info():
        return HelpInfo(
            option='leak-full',
            help_str='When set, demeuk will run the following modules: mojibake, encode, newline, check-controlchar, '
                     'hex, html, html-named, check-hash, check-mac-address, check-uuid, check-email, '
                     'check-replacement-character, check-empty-line.'
        )

    def get_submodules(self):
        encode_module = EncodeModule()
        encode_module.set_configs(self.get_config('config'))
        return [
            encode_module,
            MojibakeModule(), ControlCharModule(),
            NewlineModule(),
            HexModule(),
            HtmlModule(), HtmlNamedModule(),
            HashModule(), MacAddressModule(), UuidModule(), EmailModule(),
            ReplacementCharModule(), EmptyLineModule()
        ]



