from argparse import ArgumentParser

from modules.add import add_first_upper, add_latin_ligatures, add_without_punctuation, add_split, \
    add_umlaut, add_lower, add_title_case
from modules.check import check_starting_with, check_mac_address, check_min_length, check_uuid, \
    check_empty_line, check_max_length, check_max_specials, check_hash, check_email, \
    check_min_digits, check_case, check_min_specials, check_non_ascii, check_regex, \
    check_min_uppercase, check_max_uppercase, check_replacement_character, check_max_digits, \
    check_ending_with, check_contains, check_controlchar
from modules.modify import clean_transliterate, clean_umlaut, clean_trim, clean_hex, clean_encode, \
    clean_tab, clean_newline, clean_mojibake, clean_html, clean_title_case, clean_non_ascii, \
    clean_lowercase, clean_html_named
from modules.remove import clean_cut, remove_strip_punctuation, remove_email, remove_punctuation


# TODO think how to pack help strings in here,
# currently we determine if an option is a flag or param by looking if it is a list.
# Probably we need to do that in a better way.
# lookup tables for flags (taking no argument)
flags_check = dict({
    # Check flags
    '--check-case': check_case,
    '--check-controlchar': check_controlchar,
    '--check-email': check_email,
    '--check-hash': check_hash,
    '--check-mac-address': check_mac_address,
    '--check-uuid': check_uuid,
    '--check-non-ascii': check_non_ascii,
    '--check-replacement-character': check_replacement_character,
    '--check-empty-line': check_empty_line,
})
flags_modify = dict({
    '--html-named': clean_html_named,
    '--lowercase': clean_lowercase,
    '--title-case': clean_title_case,
    '--umlaut': clean_umlaut,
    '--mojibake': clean_mojibake,
    '--newline': clean_newline,
    '--non-ascii': clean_non_ascii,
    '--trim': clean_trim,
})
flags_add = dict({
    '--add-lower': add_lower,
    '--add-first-upper': add_first_upper,
    '--add-title-case': add_title_case,
    '--add-latin-ligatures': add_latin_ligatures,
    '--add-split': add_split,
    '--add-umlaut': add_umlaut,
    '--add-without-punctuation': add_without_punctuation,
})

flags_remove = dict({
    '--remove-strip-punctuation': remove_strip_punctuation,
    '--remove-punctuation': remove_punctuation,
    '--remove-email': remove_email,

    '-c': clean_cut,
    '--cut': clean_cut,
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
# meaning they are not order-dependent.
# You can implement modules with non-standard behaviour in the fixed pipeline.
flags_fixed = dict({
    # Modify
    '--hex': clean_hex,
    '--html': clean_html,
    '--encode': clean_encode,
    # Q: Do we want this as a normal Modify module of give it special status?
    '--tab': clean_tab,  # This is also an operation on bytes
})

# For command-line arguments with one argument.
# key = option,
# value = [function object, type of param, metavar, help]
# Type is needed for validation, might be useful for defining custom modules
# metavar and help are both used for ./demeuk.py -h
params_check = dict({
    '--check-min-length': [check_min_length, int,
                           '<length>',
                           'Requires that entries have a minimal requirement of <length> unicode chars'],
    '--check-max-length': [check_max_length, int,
                           '<length>',
                           'Requires that entries have a maximal requirement of <length> unicode chars'],
    '--check-starting-with': [check_starting_with, str,
                              '<string>', 'Drop lines starting with string, can be multiple '
                                          'strings. Specify multiple with a comma-separated list'],
    '--check-ending-with': [check_ending_with, str,
                            '<string>', 'Drop lines ending with string, can be multiple strings. '
                                        'Specify multiple with a comma-seperated list.'],
    '--check-contains': [check_contains, str,
                         '<string>', 'Drop lines containing string, can be multiple strings. '
                                     'Specify multiple with a comma-separated list'],
    '--check-regex': [check_regex, str,
                      '<string>', 'Drop lines that do not match the regex. Regex is a comma '
                                  'seperated list of regexes. Example: [a-z]{1,8},[0-9]{1,8}'],
    '--check-min-digits': [check_min_digits, int,
                           '<count>', 'Require that entries contain at least <count> digits ('
                                      'following the Python definition of a digit, '
                                      'see '
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
                                         'letters (following the Python definition of uppercase, '
                                         'see '
                                         'https://docs.python.org/3/library/stdtypes.html#str.isupper)'],
    '--check-min-special': [check_min_specials, int,
                            '<count>', 'Require that entries contain at least <count> specials (a '
                                       'special is defined as a non whitespace character which is '
                                       'not alphanumeric, following the Python definitions of '
                                       'both, see '
                                       'https://docs.python.org/3/library/stdtypes.html#str'
                                       '.isspace and '
                                       'https://docs.python.org/3/library/stdtypes.html#str.isalnum)'],
    '--check-max-special': [check_max_specials, int,
                            '<count>', 'Require that entries contain at least <count> specials (a '
                                       'special is defined as a non whitespace character which is '
                                       'not alphanumeric, following the Python definitions of '
                                       'both, see '
                                       'https://docs.python.org/3/library/stdtypes.html#str'
                                       '.isspace and '
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

lookup_flag = flags_check | flags_modify | flags_add | flags_remove
lookup_params = params_check | params_modify | params_add | params_remove


def init_parser(version):
    # Q: Do we want to keep examples in -h?
    parser = ArgumentParser(
        prog='demeuk',
        description='Demeuk - a simple tool to clean up corpora',
        usage='%(prog)s [options]',
        suggest_on_error=True,
        add_help=False  # We add our own help so that it is grouped correctly
    )

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
    group_std.add_argument('-j', '--threads', action='store', type=int,
                           metavar='<n>',
                           help='Optional, specify amount of threads to spawn. Specify the string '
                                '\'all\' to make demeuk auto detect the amount of threads to '
                                'start based on the CPU\'s (default: all threads). Note: '
                                'threading will cost some setup time. Only speeds up for larger '
                                'files.')  # TODO --threads all currently not possible
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
                           metavar='<n>',
                           help='Limit the number of lines per thread.')
    group_std.add_argument('-s', '--skip', action='store', type=int,
                           metavar='<n>',
                           help='Skip <int> amount of lines per thread.')
    group_std.add_argument('--punctuation', action='store',
                           metavar='<punctuation>',
                           help='Use to set the punctuation that is use by options. Defaults to: '
                                'string.punctuation.')
    group_std.add_argument('--version', action='version', version='%(prog)s ' + str(version),
                           help='Prints the version of demeuk.')
    group_std.add_argument('-h', '--help', action='help',
                           help='Prints this message and exits.')

    # Macro modules
    group_macro = parser.add_argument_group('Macro modules')
    group_macro.add_argument('-g', '--googlengram', action='store_true',
                             help='When set, demeuk will strip universal pos tags: like _NOUN_ or _ADJ')
    group_macro.add_argument('--leak', action='store_true',
                             help='When set, demeuk will run the following modules: mojibake, '
                                  'encode, newline, check-controlchar. This is recommended when '
                                  'working with leaks and was the default bevarior in demeuk '
                                  'version 3.11.0 and below.')
    group_macro.add_argument('--leak-full', action='store_true',
                             help='When set, demeuk will run the following modules: mojibake, '
                                  'encode, newline, check-controlchar, hex, html, html-named, '
                                  'check-hash, check-mac-address, check-uuid, check-email, '
                                  'check-replacement-character, check-empty-line.')

    # Configuring modules
    group_config = parser.add_argument_group('Configuration options')
    group_config.add_argument('-f', '--cut-fields', action='store',
                              metavar='<field>',
                              help='Specifies the field to be returned, this is in the \'cut\' '
                                   'language thus: N N\'th field, N- from N-th field to end line, '
                                   'N-M, from N-th field to M-th field. -M from start to M-th '
                                   'field.')
    group_config.add_argument('--cut-before', action='store_true',
                              help='Specify if demeuk should return the string before the '
                                   'delimiter. When cutting, demeuk by default returns the string '
                                   'after the delimiter.')
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
    for fixed_flag in flags_fixed:
        # Currently these are all modify modules.
        group_modify.add_argument(fixed_flag, action='store_true')

    # The modules in here are all executed in the order given on the command-line.
    # TODO repeated code
    for flag in flags_check:
        group_check.add_argument(flag, action='store_true')
    for flag in flags_modify:
        group_modify.add_argument(flag, action='store_true')
    for flag in flags_add:
        group_add.add_argument(flag, action='store_true')
    for flag in flags_remove:
        group_remove.add_argument(flag, action='store_true')

    for param in params_check:
        # function, type, metavar, help
        f, t, mv, h = lookup_params[param]
        group_check.add_argument(param, action='store', nargs=1, type=t, metavar=mv, help=h)

    for param in params_modify:
        f, t, mv, h = lookup_params[param]
        group_modify.add_argument(param, action='store', nargs=1, type=t, metavar=mv, help=h)

    for param in params_add:
        f, t, mv, h = lookup_params[param]
        group_add.add_argument(param, action='store', nargs=1, type=t, metavar=mv, help=h)

    for param in params_remove:
        f, t, mv, h = lookup_params[param]
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
            # el = [param, arg]
            func, t, *_ = lookup_params[el[0]]  # [func, type, metavar, helpstr]
            func_list.append([func, t(el[1])])
        else:
            func_list.append(lookup_flag[el])
    return func_list
