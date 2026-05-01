from string import punctuation as string_punctuation

from ..base import *
from ..check.check import ControlCharModule
from ..modify.encode import EncodeModule, DefaultEncodeModule
from ..modify.modify import *

from nltk import WhitespaceTokenizer, str2tuple

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
            help_str='When set, demeuk will run the following modules: mojibake, encode, newline, check-controlchar. This is recommended when working with leaks.'
        )

    def get_submodules(self):
        # We need to instantiate this explicitly because we want to pass config.
        encode_module = EncodeModule()
        encode_module.set_configs(self.get_config('config'))
        return [
            MojibakeModule(),
            encode_module,
            NewlineModule(),
            ControlCharModule(),
        ]

class GoogleNgramModule(MacroModule, ConfigModule):

    def set_configs(self, config):
        self.add_config('config', config)

    @staticmethod
    def get_help_info() -> HelpInfo | HelpInfoParam:
        return HelpInfo(
            option=['g', 'googlengram'],
            help_str='When set, demeuk will strip universal pos tags like _NOUN_ or _ADJ.'
        )

    @property
    def debug_str(self):
        return 'cleaned tags'

    def get_submodules(self):
        encode_module = EncodeModule()
        encode_module.set_configs(self.get_config('config'))
        # Disable certain modules?
        return [
            encode_module
        ]

    def run(self, line):
        """Removes speechtags from line specific to the googlengram module

        Param:
            line (unicode)

        Returns:
            line (unicode)
        """
        cleaned_line = line.split('\t')[0]  # Get the ngram, remove year, counter, etc
        clean = []
        words = WhitespaceTokenizer().tokenize(cleaned_line)
        for word in words:
            # in >1-grams transitions to specific tags are written as:
            # The_ADJ _NOUN_ (meaning from The there is a transition to a noun
            # We remove those
            if word[0] != '_' and word[-1] != '_':
                # Split the token and the tag based on the '_'
                token, tag = str2tuple(word, '_')
                # Punct will be added using rules.
                if len(token) > 1:
                    if tag != 'PUNCT' or tag != '.' or tag != '':
                        clean.append(token)
                elif token not in string_punctuation:
                    clean.append(token)
        cleaned_line = ' '.join(clean)
        if cleaned_line != line:
            return Result(status=True, msg=self.debug_str, update=cleaned_line)
        return Result(status=False, msg=None)

    def handle(self, results):
        return Actions(
            debug_str=results.msg,
            update=results.update,
        )


def clean_googlengram(line):
    """Removes speechtags from line specific to the googlengram module

    Param:
        line (unicode)

    Returns:
        line (unicode)
    """
    return_line = line.split('\t')[0]  # Get the ngram, remove year, counter, etc
    clean = []
    words = WhitespaceTokenizer().tokenize(return_line)
    for word in words:
        # in >1-grams transitions to specific tags are written as:
        # The_ADJ _NOUN_ (meaning from The there is a transition to a noun
        # We remove those
        if word[0] != '_' and word[-1] != '_':
            # Split the token and the tag based on the '_'
            token, tag = str2tuple(word, '_')
            # Punct will be added using rules.
            if len(token) > 1:
                if tag != 'PUNCT' or tag != '.' or tag != '':
                    clean.append(token)
            elif token not in string_punctuation:
                clean.append(token)
    return_line = ' '.join(clean)
    if return_line != line:
        return True, return_line, 'Clean_googlengram; tos found and removed'
    else:
        return False, line, None
