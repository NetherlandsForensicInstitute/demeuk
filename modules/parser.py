from argparse import ArgumentParser

from modules.add import *
from modules.check import *
from modules.modify import *
from modules.remove import *

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

})

flags_collections = dict({
    '--leak': '--mojibake --encode --newline --check-controlchar',
    '--leak-full': '--mojibake --encode --newline --check-controlchar --hex --html --html-named --check-hash --check-mac-address --check-uuid --check-email --check-replacement-character --check-empty-line',
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
    '--encode': clean_encode,  # Q: Do we want this as a normal Modify module of give it special status?
    '--tab': clean_tab, # This is also an operation on bytes
    # Remove
    '-c': clean_cut,
    '--cut': clean_cut
})

# For command-line arguments with one argument.
# key = option,
# value = [function object, type of param]
# Type is needed for validation, might be useful for defining custom modules
params_check = dict({
    '--check-min-length':       [check_min_length, int],
    '--check-max-length':       [check_max_length, int],
    '--check-starting-with':    [check_starting_with, str],
    '--check-ending-with':      [check_ending_with, str],
    '--check-contains':         [check_contains, str],
    '--check-regex':            [check_regex, str],
    '--check-min-digits':       [check_min_digits, int],
    '--check-max-digits':       [check_max_digits, int],
    '--check-min-uppercase':    [check_min_uppercase, int],
    '--check-max-uppercase':    [check_max_uppercase, int],
    '--check-min-special':      [check_min_specials, int],
    '--check-max-special':      [check_max_specials, int],
})
params_modify = dict({
    '--transliterate': [clean_transliterate, str],
})
params_add = dict({})
params_remove = dict({})


lookup_flag = flags_check | flags_modify | flags_add | flags_remove
lookup_params = params_check | params_modify | params_add | params_remove

def init_parser(version):
    parser = ArgumentParser(
        prog='demeuk',
        description='Demeuk - a simple tool to clean up corpora',
    )

    # Standard options
    parser.add_argument('-i', '--input', action='store')
    parser.add_argument('-o', '--output', action='store')
    parser.add_argument('-l', '--log', action='store')
    parser.add_argument('-j', '--threads', action='store', type=int) # TODO --threads all currently not possible
    parser.add_argument('--input-encoding', action='store')
    parser.add_argument('--output-encoding', action='store')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--progress', action='store_true')
    parser.add_argument('-n', '--limit', action='store', type=int)
    parser.add_argument('-s', '--skip', action='store', type=int)
    parser.add_argument('--punctuation', action='store')
    parser.add_argument('--version', action='version', version='%(prog)s ' + str(version))

    # Macro modules
    parser.add_argument('-g', '--googlengram', action='store_true')
    parser.add_argument('--leak', action='store_true')
    parser.add_argument('--leak-full', action='store_true')

    # Configuring modules
    parser.add_argument('-f', '--cut-fields', action='store')
    parser.add_argument('--cut-before', action='store_true')
    parser.add_argument('-d', '--delimiter', action='store')

    # Fixed pipeline flags
    for fixed_flag in flags_fixed:
        parser.add_argument(fixed_flag, action='store_true')

    # The modules in here are all executed in the order given on the command-line.
    for flag in lookup_flag:
        parser.add_argument(flag, action='store_true')

    for arg_param in lookup_params:
        parser.add_argument(arg_param, action='store', nargs=1, type=lookup_params[arg_param][1])
        # TODO Bad syntax

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
            func, t = lookup_params[el[0]] # [func, type]
            func_list.append([func, t(el[1])])
        else:
            func_list.append(lookup_flag[el])
    return func_list