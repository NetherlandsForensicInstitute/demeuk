from argparse import ArgumentParser, ArgumentTypeError, RawDescriptionHelpFormatter
from os import cpu_count
from textwrap import dedent

from .modules.add.add import AddModule
from .modules.base import *
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


ParserGroup = Enum('ParserGroup', [
    ('STANDARD', 0),
    ('MACRO', 1),
    ('CONFIG', 2),
    ('CHECK', 3),
    ('MODIFY', 4),
    ('ADD', 5),
    ('REMOVE', 6)])


class CommandLineParser:
    """
    A class to manage, parse and display command-line options of demeuk.
    Modules need to be registered, which uses the overridden get_help_info() to display the correct help string when
    running demeuk -h.
    """

    def __init__(self, version):
        """
        Initialize an arguments parser with just the standard options (no modules).
        :param version: demeuk version
        """
        desc = dedent("""Demeuk - a simple tool to clean up corpora

Example uses:
    demeuk -i inputfile.tmp -o outputfile.dict -l logfile.txt
    demeuk -i "inputfile*.txt" -o outputfile.dict -l logfile.txt
    demeuk -i "inputdir/*" -o outputfile.dict -l logfile.txt
    demeuk -i inputfile -o outputfile -j 24
    demeuk -i inputfile -o outputfile -c -e
    demeuk -i inputfile -o outputfile --threads all
    cat inputfile | demeuk --leak -j all | sort -u > outputfile""")

        self.parser = ArgumentParser(prog='demeuk', description=desc, usage='%(prog)s [options]',
                                add_help=False,  # We add our own help so that it is grouped correctly
                                formatter_class=RawDescriptionHelpFormatter)

        self.parser_groups = {
            ParserGroup.STANDARD: self.parser.add_argument_group('Standard options'),
            ParserGroup.MACRO: self.parser.add_argument_group('Macro modules'),
            ParserGroup.CONFIG: self.parser.add_argument_group('Configuration options'),
            ParserGroup.CHECK: self.parser.add_argument_group('Check modules (check if a line matches a specific condition)'),
            ParserGroup.MODIFY: self.parser.add_argument_group('Modify modules (modify a line in place)'),
            ParserGroup.ADD: self.parser.add_argument_group('Add modules (Modify a line, but keep the original as well)'),
            ParserGroup.REMOVE: self.parser.add_argument_group('Remove modules (remove specific parts of a line)'),
        }

        self.args = None
        self.lookup_table = {}

        # Standard options
        self.parser_groups[ParserGroup.STANDARD].add_argument('-i', '--input', action='store',
                               nargs='*',
                               metavar='<path>',
                               help='Specify the input file to be cleaned, or provide a glob pattern. (default: stdin)')
        self.parser_groups[ParserGroup.STANDARD].add_argument('-o', '--output', action='store',
                               metavar='<path>',
                               help='Specify the output file name. (default: stdout)')
        self.parser_groups[ParserGroup.STANDARD].add_argument('-l', '--log', action='store',
                               metavar='<path>',
                               help='Optional, specify where the log file needs to be writen to (default: stderr)')
        self.parser_groups[ParserGroup.STANDARD].add_argument('-j', '--threads', action='store', type=int_or_all,
                               metavar='<n>',
                               help='Optional, specify amount of threads to spawn. Specify the string '
                                    "'all' to make demeuk auto detect the amount of threads to "
                                    "start based on the CPU's (default: all threads). Note: "
                                    'threading will cost some setup time. Only speeds up for larger files.')
        self.parser_groups[ParserGroup.STANDARD].add_argument('-v', '--verbose', action='store_true',
                               help='When set, printing some extra information to stderr. And will '
                                    'print the lines containing errors to logfile.')
        self.parser_groups[ParserGroup.STANDARD].add_argument('--debug', action='store_true',
                               help='When set, the logfile will not only contain lines which caused '
                                    'an error, but also line which were modified.')
        self.parser_groups[ParserGroup.STANDARD].add_argument('--progress', action='store_true',
                               help='Prints out the progress of the demeuk process.')
        self.parser_groups[ParserGroup.STANDARD].add_argument('-n', '--limit', action='store', type=int,
                               metavar='<n>', help='Limit the number of lines per thread.')
        self.parser_groups[ParserGroup.STANDARD].add_argument('-s', '--skip', action='store', type=int,
                               metavar='<n>', help='Skip <int> amount of lines per thread.')
        self.parser_groups[ParserGroup.STANDARD].add_argument('--version', action='version',
                                                    version=f'%(prog)s {version}', help='Prints the version of demeuk.')
        self.parser_groups[ParserGroup.STANDARD].add_argument('-h', '--help', action='help',
                               help='Prints this message and exits.')

        # Configuration options
        self.parser_groups[ParserGroup.CONFIG].add_argument('--input-encoding', action='store',
                                                    metavar='<encoding>',
                                                    help='Forces demeuk to decode the input using this encoding (default: en_US.UTF-8).')
        self.parser_groups[ParserGroup.CONFIG].add_argument('--output-encoding', action='store',
                                                    metavar='<encoding>',
                                                    help='Forces demeuk to encoding the output using this encoding (default: en_US.UTF-8).')
        self.parser_groups[ParserGroup.CONFIG].add_argument('--punctuation', action='store',
                                                    metavar='<punctuation>',
                                                    help='Use to set the punctuation that is use by options. Defaults to: string.punctuation.')
        self.parser_groups[ParserGroup.CONFIG].add_argument('-f','--cut-fields', action='store',
                                                  metavar='<field>',
                                                  help="Specifies the field to be returned, this is in the 'cut' syntax.")
        self.parser_groups[ParserGroup.CONFIG].add_argument('--cut-before', action='store_true',
                                                  help='Specify if demeuk should return the string before the delimiter')
        self.parser_groups[ParserGroup.CONFIG].add_argument('-d', '--delimiter', action='store',
                                                  metavar='<delimiters>',
                                                  help="Specify what delimiter to use for --cut. Multiple delimiters can be specified with ','")

    @staticmethod
    def make_cli_option(option):
        """
        Transforms a string into a command-line option: For example 'c' to '-c' and 'cut' to '--cut'.
        :param option: A string to transform
        :return: The resulting option
        """
        if len(option) == 1:
            return '-' + option
        else:
            return '--' + option

    @staticmethod
    def make_cli_options(options):
        """
        Transform a string or a list of strings into a list of command-line options.
        :param options: A string or list of strings to transform
        :return: A list of options
        """
        if isinstance(options, str):
            return [CommandLineParser.make_cli_option(options)]
        else:
            return [CommandLineParser.make_cli_option(option) for option in options]

    @staticmethod
    def make_cli_options_from_module(module):
        """
        Use a modules get_help_info() to get its list of command-line options.
        :param module: A module
        :return: A list of command-line options
        """
        return CommandLineParser.make_cli_options(module.get_help_info().option)


    def add_flag_options(self, group, help_info):
        """
        Add options to the argument parser so that they are recognized on the command-line.
        This is for flags, which are command-line options which do not take an argument.
        :param group: The category in which to list the option(s).
        :param help_info: The HelpInfo object containing the option and help string.
        """
        options = self.make_cli_options(help_info.option)
        self.parser_groups[group].add_argument(
            *options,
            help=help_info.help_str,
            action='store_true')

    def add_param_options(self, group, help_info_param):
        """
        Add options to the argument parser so that they are recognized on the command-line.
        This is for parameters, which are command-line options which take one argument.
        :param group: The category in which to list the option(s).
        :param help_info_param: The HelpInfoParam object containing the option and help string, and info about the parameter.
        """
        options = self.make_cli_options(help_info_param.option)
        self.parser_groups[group].add_argument(
            *options,
            help=help_info_param.help_str,
            metavar=help_info_param.metavar,
            type=help_info_param.param_type,
            action='store')



    def register(self, module):
        """
        Register a module to the argument parser
        :param module: The module to register
        """
        # Hardcoded: Module Type determines help category
        categories = {
            CheckModule: ParserGroup.CHECK,
            ModifyModule: ParserGroup.MODIFY,
            AddModule: ParserGroup.ADD,
            RemoveModule: ParserGroup.REMOVE,
            MacroModule: ParserGroup.MACRO,
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


        for option in CommandLineParser.make_cli_options_from_module(module):
            self.lookup_table[option] = module

    def parse_args(self, args):
        """
        Parse arguments, this needs to be done after all modules are registered.
        :param args: A list of command-line arguments (for example sys.argv).
        """
        self.args = self.parser.parse_args(args[1:]) # First arg is program name, we don't need that