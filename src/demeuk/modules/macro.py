from string import punctuation as string_punctuation

from demeuk.modules.base import *
from demeuk.modules.encode import *

from nltk import WhitespaceTokenizer, str2tuple

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
            help_str='When wet, demeuk will run the following modules: mojibake, encode, newline, check-controlchar. This is recommended when working with leaks.'
        )

    def get_submodules(self):
        encode_module = EncodeModule()
        encode_module.set_configs(self.get_config('config'))
        return [
            CleanTrimModifyModule(),
            HexModule(),
            encode_module,
            TabModule(),
        ]


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
