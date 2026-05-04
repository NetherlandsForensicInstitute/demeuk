# - Remove module -
# Remove modules can remove parts of a line.
# These take a line as input, possibly with an argument.
# The module should return a bool result, a str out_line and a str log
# result is False if nothing was changed.
# out_line is the result of the operation
# log is a debug string which can be None. Logged when result is True (something changed)
from re import search, sub

from demeuk.regexes import EMAIL_REGEX
from demeuk.modules.add.add import get_punctuation, global_store_punctuation


global_store_delims = [':']
global_store_cut_fields = '2-'


def set_delim(delim):
    global global_store_delims
    splitter = ','
    # We can have comma as delimiter, if we put it first and separate with semicolon.
    if len(delim) >= 1:
        if delim[0] == ',':
            splitter = ';'
    global_store_delims = delim.split(splitter)


def get_delim():
    return global_store_delims


def set_cut_fields(cut_fields):
    global global_store_cut_fields
    global_store_cut_fields = cut_fields


def get_cut_fields():
    return global_store_cut_fields


def remove_strip_punctuation(line):
    """Returns the line without start and end punctuation

    Param:
        line (unicode)

    Returns:
        line without start and end punctuation
    """
    return_line = line.strip(global_store_punctuation)
    if return_line != line:
        return True, return_line, 'Remove_strip_punctuation; stripped punctuation'
    else:
        return False, line, None


def remove_punctuation(line):
    """Returns the line without punctuation

    Param:
        line (unicode)
        punctuation (unicode)

    Returns:
        line without start and end punctuation
    """
    return_line = line.translate(str.maketrans('', '', get_punctuation()))
    if return_line != line:
        return True, return_line, 'Remove_punctuation; stripped punctuation'
    else:
        return False, line, None


def remove_email(line):
    """Removes e-mail addresses from a line.

    Params:
        line (unicode)

    Returns:
        line (unicode)
    """
    if '@' in line:
        if search(f'{EMAIL_REGEX}(:|;)', line):
            return True, sub(f'{EMAIL_REGEX}(:|;)', '', line), 'Remove_email; email found'
    return False, line, None