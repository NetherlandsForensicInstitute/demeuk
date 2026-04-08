from modules.regexes import *

def remove_strip_punctuation(line, punctuation):
    """Returns the line without start and end punctuation

    Param:
        line (unicode)

    Returns:
        line without start and end punctuation
    """
    return_line = line.strip(punctuation)
    if return_line != line:
        return True, return_line
    else:
        return False, line

def remove_punctuation(line, punctuation):
    """Returns the line without punctuation

    Param:
        line (unicode)
        punctuation (unicode)

    Returns:
        line without start and end punctuation
    """
    return_line = line.translate(str.maketrans('', '', punctuation))
    if return_line != line:
        return True, return_line
    else:
        return False, line


def remove_email(line):
    """Removes e-mail addresses from a line.

    Params:
        line (unicode)

    Returns:
        line (unicode)
    """
    if '@' in line:
        if search(f'{EMAIL_REGEX}(:|;)', line):
            return True, sub(f'{EMAIL_REGEX}(:|;)', '', line)
    return False, line
