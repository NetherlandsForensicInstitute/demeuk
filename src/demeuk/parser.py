import sys
from argparse import ArgumentParser, RawDescriptionHelpFormatter, ArgumentTypeError
from enum import Enum
from textwrap import dedent

from .modules.add import *
from .modules.check import *
from .modules.modify import *
from .modules.remove import *
from multiprocess import cpu_count

# Enums for option types
OptionType = Enum('OptionType', [('FLAG', 0), ('PARAM', 1)])
ModuleType = Enum('ModuleType', [('CHECK', 0), ('MODIFY', 1), ('ADD', 2), ('REMOVE', 3)])

# lookup tables for flags (taking no argument)
flags_check = dict({
    '--check-case': [check_case, 'Drop lines where the uppercase line is not equal to the lowercase line'],
    '--check-controlchar': [check_controlchar, 'Drop lines containing control chars.'],
    '--check-email': [check_email, 'Drop lines containing e-mail addresses.'],
    '--check-hash': [check_hash, 'Drop lines which are hashes.'],
    '--check-mac-address': [check_mac_address, 'Drop lines which are MAC-addresses.'],
    '--check-uuid': [check_uuid, 'Drop lines which are UUID.'],
    '--check-non-ascii': [check_non_ascii, 'If a line contain a non ascii char e.g. ü or ç (or '
                                           'everything outside ascii range) the line is dropped.'],
    '--check-replacement-character': [check_replacement_character, 'Drop lines containing '
                                                                   'replacement characters \'�\'.'],
    '--check-empty-line': [check_empty_line, 'Drop lines that are empty or only contain whitespace characters'],
})
flags_modify = dict({
    '--html-named': [clean_html_named, 'Replace lines like: &#alpha; Those structures are more '
                                       'like passwords, so be careful to enable this option.'],
    '--lowercase': [clean_lowercase, 'Replace line like \'This Test String\' to \'this test string\''],
    '--title-case': [clean_title_case, 'Replace line like \'this test string\' to \'This Test String\''],
    '--umlaut': [clean_umlaut, 'Replace lines like ko"ffie with an o with an umlaut.'],
    '--mojibake': [clean_mojibake, 'Fixes mojibakes, which means lines like SmˆrgÂs will be fixed to Smörgås.'],
    '--newline': [clean_newline, 'Enables removing newline characters (\'\\r\' and \'\\n\') from end and beginning of '
                                 'lines.'],
    '--non-ascii': [clean_non_ascii, 'Replace non ascii char with their replacement letters. For '
                                     'example ü becomes u, ç becomes c.'],
    '--trim': [clean_trim, 'Enables removing newlines representations from end and beginning. '
                           'Newline representations detected are \'\\\\n\', \'\\\\r\', \'\\n\', '
                           '\'\\r\', \'<br>\', and \'<br />\'.'],
})

flags_add = dict({
    '--add-lower': [add_lower, 'If a line contains a capital letter this will add the lower case variant'],
    '--add-first-upper': [add_first_upper, 'If a line does not contain a capital letter this will add the capital '
                                           'variant'],
    '--add-title-case': [add_title_case, 'Add a line like \'this test string\' also as a \'This Test String\''],
    '--add-latin-ligatures': [add_latin_ligatures, 'If a line contains a single ligatures of a latin letter '
                                                   '(such as ij), the line is correct but the original line contain '
                                                   'the ligatures is also added to output.'],
    '--add-split': [add_split, 'split on known chars like - and . and add those to the final dictionary.'],
    '--add-umlaut': [add_umlaut, 'In some spelling dicts, umlaut are sometimes written as: o" or i" and not as one '
                                 'char.'],
    '--add-without-punctuation': [add_without_punctuation, 'If a line contains punctuations, '
                                                           'a variant will be added without the punctuations'],
})

flags_remove = dict({
    '--remove-strip-punctuation': [remove_strip_punctuation, 'Remove starting and trailing punctuation'],
    '--remove-punctuation': [remove_punctuation, 'Remove all punctuation in a line'],
    '--remove-email': [remove_email, 'Enable email filter, this will catch strings like '
                                     '1238661:test@example.com:password'],

    '-c': [clean_cut, 'Specify if demeuk should split (default splits on \':\'). Returns '
                      'everything after the delimiter.'],
    '--cut': [clean_cut, 'Alias for -c.'],
})

flags_collections = dict({
    '--leak': '--mojibake --encode --newline --check-controlchar',
    '--leak-full': '--mojibake --encode --newline --check-controlchar --hex --html --html-named '
                   '--check-hash --check-mac-address --check-uuid --check-email '
                   '--check-replacement-character --check-empty-line',
    '-g': '--encoding',
    '--googlengram': '--encoding',
})

# These modules are part of the _fixed part_ of the function pipeline,
# meaning they are not order-dependent. Tab acts on bytes, encode takes bytes and returns str.
# You can implement modules with non-standard behaviour in the fixed pipeline.
flags_fixed = dict({
    # Modify
    '--hex': [clean_hex, 'Replace lines like: $HEX[41424344] with ABCD.'],
    '--html': [clean_html, 'Replace lines like: &#351;ifreyok with şifreyok.'],
    '--encode': [clean_encode, 'Enables guessing of encoding, based on chardet and custom implementation.'],
    '--tab': [clean_tab, 'Enables replacing tab char with \':\', sometimes leaks contain both \':\' and \'\\t\'.'],
})

# For command-line arguments with one argument.
# key = option, value = [function object, type of param, metavar, help]
# Type is needed for validation, might be useful for defining custom modules
# metavar and help are both used for ./demeuk.py -h
params_check = dict({
    '--check-min-length': [check_min_length, int,
                           '<length>', 'Requires that entries have a minimal requirement of <length> unicode chars'],
    '--check-max-length': [check_max_length, int,
                           '<length>', 'Requires that entries have a maximal requirement of <length> unicode chars'],
    '--check-starting-with': [check_starting_with, str,
                              '<string>', 'Drop lines starting with string, can be multiple '
                                          'strings. Specify multiple with a comma-separated list'],
    '--check-ending-with': [check_ending_with, str,
                            '<string>', 'Drop lines ending with string, can be multiple strings. '
                                        'Specify multiple with a comma-separated list.'],
    '--check-contains': [check_contains, str,
                         '<string>', 'Drop lines containing string, can be multiple strings. '
                                     'Specify multiple with a comma-separated list'],
    '--check-regex': [check_regex, str,
                      '<string>', 'Drop lines that do not match the regex. Regex is a comma '
                                  'separated list of regexes. Example: [a-z]{1,8},[0-9]{1,8}'],
    '--check-min-digits': [check_min_digits, int,
                           '<count>', 'Require that entries contain at least <count> digits ('
                                      'following the Python definition of a digit, see '
                                      'https://docs.python.org/3/library/stdtypes.html#str.isdigit)'],
    '--check-max-digits': [check_max_digits, int,
                           '<count>', 'Require that entries contain at most <count> digits ('
                                      'following the Python definition of a digit, see '
                                      'https://docs.python.org/3/library/stdtypes.html#str.isdigit)'],
    '--check-min-uppercase': [check_min_uppercase, int,
                              '<count>', 'Require that entries contain at least <count> uppercase '
                                         'letters (following the Python definition of uppercase, see '
                                         'https://docs.python.org/3/library/stdtypes.html#str.isupper)'],
    '--check-max-uppercase': [check_max_uppercase, int,
                              '<count>', 'Require that entries contain at most <count> uppercase '
                                         'letters (following the Python definition of uppercase, see '
                                         'https://docs.python.org/3/library/stdtypes.html#str.isupper)'],
    '--check-min-special': [check_min_specials, int,
                            '<count>', 'Require that entries contain at least <count> specials (a '
                                       'special is defined as a non whitespace character which is '
                                       'not alphanumeric, following the Python definitions of both, see '
                                       'https://docs.python.org/3/library/stdtypes.html#str.isspace and '
                                       'https://docs.python.org/3/library/stdtypes.html#str.isalnum)'],
    '--check-max-special': [check_max_specials, int,
                            '<count>', 'Require that entries contain at least <count> specials (a '
                                       'special is defined as a non whitespace character which is '
                                       'not alphanumeric, following the Python definitions of both, see '
                                       'https://docs.python.org/3/library/stdtypes.html#str.isspace and '
                                       'https://docs.python.org/3/library/stdtypes.html#str.isalnum)'],
})
params_modify = dict({
    '--transliterate': [clean_transliterate, str,
                        '<language>', 'Transliterate a strings, for example "ipsum" becomes '
                                      '"իպսում". The following languages are supported: ka, sr, '
                                      'l1, ru, mn, uk, mk, el, hy and bg.'],
})
params_add = dict({})
params_remove = dict({})

# Dict concatenation with | can only be done from python 3.9+
# Earlier versions use uglier syntax
if sys.version_info < (3, 9):
    lookup_flag = {**flags_check, **flags_modify, **flags_add, **flags_remove}
    lookup_params = {**params_check, **params_modify, **params_add, **params_remove}
else:
    lookup_flag = flags_check | flags_modify | flags_add | flags_remove
    lookup_params = params_check | params_modify | params_add | params_remove


# -j can take int or 'all' as argument.
def int_or_all(arg):
    try:
        return int(arg)
    except ValueError:
        pass
    if arg == 'all':
        return cpu_count()
    raise ArgumentTypeError(f'invalid value {arg} not int or \'all\'')


def init_parser(version):
    desc = dedent('''Demeuk - a simple tool to clean up corpora

Example uses:
    ./demeuk.py -i inputfile.tmp -o outputfile.dict -l logfile.txt
    ./demeuk.py -i "inputfile*.txt" -o outputfile.dict -l logfile.txt
    ./demeuk.py -i "inputdir/*" -o outputfile.dict -l logfile.txt
    ./demeuk.py -i inputfile -o outputfile -j 24
    ./demeuk.py -i inputfile -o outputfile -c -e
    ./demeuk.py -i inputfile -o outputfile --threads all
    cat inputfile | ./demeuk.py --leak -j all | sort -u > outputfile''')

    parser = ArgumentParser(prog='demeuk', description=desc, usage='./%(prog)s.py [options]',
                            add_help=False,  # We add our own help so that it is grouped correctly
                            formatter_class=RawDescriptionHelpFormatter)

    # Standard options
    group_std = parser.add_argument_group('Standard options')
    group_std.add_argument('-i', '--input', action='store',
                           metavar='<path>',
                           help='Specify the input file to be cleaned, or provide a glob pattern. (default: stdin)')
    group_std.add_argument('-o', '--output', action='store',
                           metavar='<path>',
                           help='Specify the output file name. (default: stdout)')
    group_std.add_argument('-l', '--log', action='store',
                           metavar='<path>',
                           help='Optional, specify where the log file needs to be writen to (default: stderr)')
    group_std.add_argument('-j', '--threads', action='store', type=int_or_all,
                           metavar='<n>',
                           help='Optional, specify amount of threads to spawn. Specify the string '
                                '\'all\' to make demeuk auto detect the amount of threads to '
                                'start based on the CPU\'s (default: all threads). Note: '
                                'threading will cost some setup time. Only speeds up for larger files.')
    group_std.add_argument('--input-encoding', action='store',
                           metavar='<encoding>',
                           help='Forces demeuk to decode the input using this encoding (default: en_US.UTF-8).')
    group_std.add_argument('--output-encoding', action='store',
                           metavar='<encoding>',
                           help='Forces demeuk to encoding the output using this encoding (default: en_US.UTF-8).')
    group_std.add_argument('-v', '--verbose', action='store_true',
                           help='When set, printing some extra information to stderr. And will '
                                'print the lines containing errors to logfile.')
    group_std.add_argument('--debug', action='store_true',
                           help='When set, the logfile will not only contain lines which caused '
                                'an error, but also line which were modified.')
    group_std.add_argument('--progress', action='store_true',
                           help='Prints out the progress of the demeuk process.')
    group_std.add_argument('-n', '--limit', action='store', type=int,
                           metavar='<n>', help='Limit the number of lines per thread.')
    group_std.add_argument('-s', '--skip', action='store', type=int,
                           metavar='<n>', help='Skip <int> amount of lines per thread.')
    group_std.add_argument('--punctuation', action='store',
                           metavar='<punctuation>',
                           help='Use to set the punctuation that is use by options. Defaults to: string.punctuation.')
    group_std.add_argument('--version', action='version', version='%(prog)s ' + str(version),
                           help='Prints the version of demeuk.')
    group_std.add_argument('-h', '--help', action='help',
                           help='Prints this message and exits.')

    # Macro modules
    group_macro = parser.add_argument_group('Macro modules')
    group_macro.add_argument('-g', '--googlengram', action='store_true',
                             help='When set, demeuk will strip universal pos tags: like _NOUN_ or _ADJ')
    group_macro.add_argument('--leak', action='store_true',
                             help='When set, demeuk will run the following modules: mojibake, encode, newline, '
                                  'check-controlchar. This is recommended when working with leaks and was the default '
                                  'bevarior in demeuk version 3.11.0 and below.')
    group_macro.add_argument('--leak-full', action='store_true',
                             help='When set, demeuk will run the following modules: mojibake, encode, newline, '
                                  'check-controlchar, hex, html, html-named, check-hash, check-mac-address, '
                                  'check-uuid, check-email, check-replacement-character, check-empty-line.')

    # Configuring modules
    group_config = parser.add_argument_group('Configuration options')
    group_config.add_argument('-f', '--cut-fields', action='store',
                              metavar='<field>',
                              help='Specifies the field to be returned, this is in the \'cut\' '
                                   'language thus: N N\'th field, N- from N-th field to end line, '
                                   'N-M, from N-th field to M-th field. -M from start to M-th field.')
    group_config.add_argument('--cut-before', action='store_true',
                              help='Specify if demeuk should return the string before the '
                                   'delimiter. When cutting, demeuk by default returns the string after the delimiter.')
    group_config.add_argument('-d', '--delimiter', action='store',
                              metavar='<delimiter>',
                              help='Specify which delimiter will be used for cutting. Multiple '
                                   'delimiters can be specified using \',\'. If the \','
                                   '\' is required for cutting, escape it with a backslash. Only '
                                   'one delimiter can be used per line.')

    group_check = parser.add_argument_group(
        'Check modules (check if a line matches a specific condition)')
    group_modify = parser.add_argument_group('Modify modules (modify a line in place)')
    group_add = parser.add_argument_group(
        'Add modules (Modify a line, but keep the original as well)')
    group_remove = parser.add_argument_group('Remove modules (remove specific parts of a line)')

    # Fixed pipeline flags
    for flag in flags_fixed:
        # Currently these are all modify modules.
        _, h = flags_fixed[flag]
        group_modify.add_argument(flag, action='store_true', help=h)

    # The modules in here are all executed in the order given on the command-line.
    # TODO repeated code
    for flag in flags_check:
        _, h = lookup_flag[flag]
        group_check.add_argument(flag, action='store_true', help=h)
    for flag in flags_modify:
        _, h = lookup_flag[flag]
        group_modify.add_argument(flag, action='store_true', help=h)
    for flag in flags_add:
        _, h = lookup_flag[flag]
        group_add.add_argument(flag, action='store_true', help=h)
    for flag in flags_remove:
        _, h = lookup_flag[flag]
        group_remove.add_argument(flag, action='store_true', help=h)

    for param in params_check:
        # function, type, metavar, help
        _, t, mv, h = lookup_params[param]
        group_check.add_argument(param, action='store', nargs=1, type=t, metavar=mv, help=h)

    for param in params_modify:
        _, t, mv, h = lookup_params[param]
        group_modify.add_argument(param, action='store', nargs=1, type=t, metavar=mv, help=h)

    for param in params_add:
        _, t, mv, h = lookup_params[param]
        group_add.add_argument(param, action='store', nargs=1, type=t, metavar=mv, help=h)

    for param in params_remove:
        _, t, mv, h = lookup_params[param]
        group_remove.add_argument(param, action='store', nargs=1, type=t, metavar=mv, help=h)

    return parser


def parse_order(argv):
    ordered_list = []
    for i in range(1, len(argv)):
        arg = argv[i]
        if arg in lookup_flag:
            ordered_list.append(arg)
        elif arg in lookup_params:
            # Existence of argv[i+1] should be guaranteed by argparse check.
            ordered_list.append([arg, argv[i + 1]])
        elif arg in flags_collections:
            for a in flags_collections[arg].split(' '):
                if a in lookup_flag:
                    ordered_list.append(a)

    return ordered_list


def get_pipeline(ordered_list):
    func_list = []
    for el in ordered_list:
        if isinstance(el, list):
            # Function with arguments
            param, arg = el  # Unpack element
            func, t, *_ = lookup_params[param]  # [func, type, metavar, helpstr]
            func_list.append([func, t(arg)])
        else:
            func, *_ = lookup_flag[el]
            func_list.append(func)
    return func_list


# Determine type info (flag/param, module type) once so that we don;t have to check this every loop.
def get_type_info(ordered_list):
    type_info = []
    for el in ordered_list:
        # [0]: 'f'lag, 'p'aram
        # [1]: 'c'heck, 'm'odify, 'a'dd, 'r'emove
        current_type = [] # TODO use enum?
        if isinstance(el, list):
            opt, _ = el
            current_type.append(OptionType.PARAM)
        else:
            opt = el
            current_type.append(OptionType.FLAG)

        if opt in flags_check | params_check:
            current_type.append(ModuleType.CHECK)
        elif opt in flags_modify | params_modify:
            current_type.append(ModuleType.MODIFY)
        elif opt in flags_add | params_add:
            current_type.append(ModuleType.ADD)
        elif opt in flags_remove | params_remove:
            current_type.append(ModuleType.REMOVE)
        type_info.append(current_type)
    return type_info
