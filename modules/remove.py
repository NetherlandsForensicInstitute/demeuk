### - Remove module -
# Remove modules can remove parts of a line.
# These take a line as input, possibly with an argument.
# The module should return a bool result, a str out_line and a str log
# result is False if nothing was changed.
# out_line is the result of the operation
# log is a debug string which can be None. Logged when result is True (something changed)
from modules.add import global_store_punctuation, get_punctuation
from modules.regexes import *

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
    # NB: here we use the global punctutation variable.
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

global_store_delims = [':']
global_store_cut_fields = '2-'

def set_delim(delim):
    global global_store_delims
    global_store_delims = delim

# TODO looks like we need getters/setters for global var?
def get_delim():
    return global_store_delims


def set_cut_fields(cut_fields):
    global global_store_cut_fields
    global_store_cut_fields = cut_fields

def get_cut_fields():
    return global_store_cut_fields

# In the docs, cut is a separating module
# I think it cna also be viewed as a remove module.
def clean_cut(line, delimiters, fields):
    """Finds the first delimiter and returns the remaining string either after
    or before the delimiter.

    Params:
        line (unicode)
        delimiters list(unicode)
        fields (unicode)

    Returns:
        line (unicode)
    """
    for delimiter in delimiters:
        if delimiter in line:
            if '-' in fields:
                start = fields.split('-')[0]
                stop = fields.split('-')[1]
                if start == '':
                    start = 1
                if stop == '':
                    stop = len(line)
                fields = slice(int(start) - 1, int(stop))
            else:
                fields = slice(int(fields) - 1, int(fields))
            return True, delimiter.join(line.split(delimiter)[fields])
    else:
        return False, line
