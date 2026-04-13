### - Remove module -
# Remove modules can remove parts of a line.
# These take a line as input, possibly with an argument.
# The module should return a bool result, a str out_line and a str log
# result is False if nothing was changed.
# out_line is the result of the operation
# log is a debug string which can be None. Logged when result is True (something changed)
from modules.add import global_store_punctuation
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
        return True, return_line, f'Remove_strip_punctuation; stripped punctuation'
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
    return_line = line.translate(str.maketrans('', '', global_store_punctuation))
    if return_line != line:
        return True, return_line, f'Remove_punctuation; stripped punctuation'
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
            return True, sub(f'{EMAIL_REGEX}(:|;)', '', line), f'Remove_email; email found'
    return False, line, None
