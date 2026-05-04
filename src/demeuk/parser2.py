from argparse import ArgumentTypeError, ArgumentParser, RawDescriptionHelpFormatter
from os import cpu_count
from textwrap import dedent

from .modules.base import *
from .modules.add.add import AddModule
from .modules.check.check import CheckModule
from .modules.macro.macro import MacroModule
from .modules.modify.modify import ModifyModule
from .modules.remove.remove import RemoveModule


# -j can take int or 'all' as argument.
def int_or_all(arg):
    try:
        return int(arg)
    except ValueError:
        pass
    if arg == 'all':
        return cpu_count()
    raise ArgumentTypeError(f"invalid value {arg} not int or 'all'")



class Parser:
    def __init__(self, version):
        desc = dedent("""Demeuk - a simple tool to clean up corpora

Example uses:
    pdm run demeuk -i inputfile.tmp -o outputfile.dict -l logfile.txt
    pdm run demeuk -i "inputfile*.txt" -o outputfile.dict -l logfile.txt
    pdm run demeuk -i "inputdir/*" -o outputfile.dict -l logfile.txt
    pdm run demeuk -i inputfile -o outputfile -j 24
    pdm run demeuk -i inputfile -o outputfile -c -e
    pdm run demeuk -i inputfile -o outputfile --threads all
    cat inputfile | pdm run demeuk --leak -j all | sort -u > outputfile""")

        self.parser = ArgumentParser(prog='demeuk', description=desc, usage='pdm run %(prog)s [options]',
                                add_help=False,  # We add our own help so that it is grouped correctly
                                formatter_class=RawDescriptionHelpFormatter)

        # Do we want strings as keys? Or create an enum just for the parser groups
        self.parser_groups = {
            'standard': self.parser.add_argument_group('Standard options'),
            'macro': self.parser.add_argument_group('Macro modules'),
            'config': self.parser.add_argument_group('Configuration options'),
            'check': self.parser.add_argument_group('Check modules (check if a line matches a specific condition)'),
            'modify': self.parser.add_argument_group('Modify modules (modify a line in place)'),
            'add': self.parser.add_argument_group('Add modules (Modify a line, but keep the original as well)'),
            'remove': self.parser.add_argument_group('Remove modules (remove specific parts of a line)'),
        }

        self.args = None
        self.order = []
        self.lookup_table = {}

        # Standard options
        self.parser_groups['standard'].add_argument('-i', '--input', action='store',
                               metavar='<path>',
                               help='Specify the input file to be cleaned, or provide a glob pattern. (default: stdin)')
        self.parser_groups['standard'].add_argument('-o', '--output', action='store',
                               metavar='<path>',
                               help='Specify the output file name. (default: stdout)')
        self.parser_groups['standard'].add_argument('-l', '--log', action='store',
                               metavar='<path>',
                               help='Optional, specify where the log file needs to be writen to (default: stderr)')
        self.parser_groups['standard'].add_argument('-j', '--threads', action='store', type=int_or_all,
                               metavar='<n>',
                               help='Optional, specify amount of threads to spawn. Specify the string '
                                    "'all' to make demeuk auto detect the amount of threads to "
                                    "start based on the CPU's (default: all threads). Note: "
                                    'threading will cost some setup time. Only speeds up for larger files.')
        self.parser_groups['standard'].add_argument('-v', '--verbose', action='store_true',
                               help='When set, printing some extra information to stderr. And will '
                                    'print the lines containing errors to logfile.')
        self.parser_groups['standard'].add_argument('--debug', action='store_true',
                               help='When set, the logfile will not only contain lines which caused '
                                    'an error, but also line which were modified.')
        self.parser_groups['standard'].add_argument('--progress', action='store_true',
                               help='Prints out the progress of the demeuk process.')
        self.parser_groups['standard'].add_argument('-n', '--limit', action='store', type=int,
                               metavar='<n>', help='Limit the number of lines per thread.')
        self.parser_groups['standard'].add_argument('-s', '--skip', action='store', type=int,
                               metavar='<n>', help='Skip <int> amount of lines per thread.')
        self.parser_groups['standard'].add_argument('--version', action='version', version='%(prog)s ' + str(version),
                               help='Prints the version of demeuk.')
        self.parser_groups['standard'].add_argument('-h', '--help', action='help',
                               help='Prints this message and exits.')

        # Configuration options
        self.parser_groups['config'].add_argument('--input-encoding', action='store',
                                                    metavar='<encoding>',
                                                    help='Forces demeuk to decode the input using this encoding (default: en_US.UTF-8).')
        self.parser_groups['config'].add_argument('--output-encoding', action='store',
                                                    metavar='<encoding>',
                                                    help='Forces demeuk to encoding the output using this encoding (default: en_US.UTF-8).')
        self.parser_groups['config'].add_argument('--punctuation', action='store',
                                                    metavar='<punctuation>',
                                                    help='Use to set the punctuation that is use by options. Defaults to: string.punctuation.')
        self.parser_groups['config'].add_argument('-f','--cut-fields', action='store',
                                                  metavar='<field>',
                                                  help="Specifies the field to be returned, this is in the 'cut' language.")
        # TODO do we want to explain cut in helpstr?
        self.parser_groups['config'].add_argument('--cut-before', action='store_true',
                                                  help='Specify if demeuk should return the string before the delimiter')
        # Desribe default behavior of cut inside of CutModule
        self.parser_groups['config'].add_argument('-d', '--delimiter', action='store',
                                                  metavar='<delimiters>',
                                                  help="Specify what delimiter to use for --cut. Multiple delimiteres can be specified with ','")

    # Resolve 'g' -> '-g' and 'check-something' -> '--check-something'
    @staticmethod
    def make_cli_option(option):
        if len(option) == 1:
            return '-' + option
        else:
            return '--' + option

    # The above, but allow string or list[str]
    @staticmethod
    def make_cli_options(options):
        if isinstance(options, str):
            return [Parser.make_cli_option(options)]
        else:
            return [Parser.make_cli_option(option) for option in options]

    # Utility function, get a list of cli options from a module
    @staticmethod
    def make_cli_options_from_module(module):
        return Parser.make_cli_options(module.get_help_info().option)


    def add_flag_options(self, group, help_info):
        options = self.make_cli_options(help_info.option)
        self.parser_groups[group].add_argument(
            *options,
            help=help_info.help_str,
            action='store_true')

    def add_param_options(self, group, help_info_param):
        options = self.make_cli_options(help_info_param.option)
        self.parser_groups[group].add_argument(
            *options,
            help=help_info_param.help_str,
            metavar=help_info_param.metavar,
            type=help_info_param.param_type,
            action='store')



    def register(self, module):
        # Hardcoded: Module Type determines help category
        categories = {
            CheckModule: 'check',
            ModifyModule: 'modify',
            AddModule: 'add',
            RemoveModule: 'remove',
            MacroModule: 'macro',
        }

        for module_type, group_str in categories.items():
            if issubclass(module, module_type):
                group = group_str
                break
        else:
            # If a module is not one of the categories, don't register.
            # Therefore, it cannot be called from the command-line, only internally!
            return

        if issubclass(module, ParamModule):
            self.add_param_options(group, module.get_help_info())
        else:
            self.add_flag_options(group, module.get_help_info())


        for option in Parser.make_cli_options_from_module(module):
            self.lookup_table[option] = module

    # Parse arguments and set global config
    def parse_args(self):
        self.args = self.parser.parse_args()